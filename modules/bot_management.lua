-- emubot/modules/bot_management.lua
-- Simple bot management tab: list bots with quick actions (spawn, invite to group, camp)

local mq = require('mq')
local bot_inventory = require('EmuBot.modules.bot_inventory')
local race_class_utils = require('EmuBot.modules.race_class_utils')
local applyTableSort = require('EmuBot.modules.ui_table_utils').applyTableSort

local M = {}

-- Canonical class names (ordered longest first to prefer multi-word matches)
local CLASS_NAMES = {
    'Shadowknight',
    'Necromancer',
    'Beastlord',
    'Berserker',
    'Magician',
    'Enchanter',
    'Paladin',
    'Ranger',
    'Warrior',
    'Cleric',
    'Shaman',
    'Wizard',
    'Druid',
    'Monk',
    'Rogue',
    'Bard',
}

local function canonicalize_class(raw)
    if not raw or raw == '' then return nil end
    local s = tostring(raw)
    -- Exact match first
    for _, cname in ipairs(CLASS_NAMES) do
        if s:lower() == cname:lower() then return cname end
    end
    -- Substring match (handles things like 'Elf Rogue', 'Shir Bard')
    local low = s:lower()
    for _, cname in ipairs(CLASS_NAMES) do
        local cl = cname:lower()
        if low:find(cl, 1, true) then
            return cname
        end
    end
    -- Fallback: strip first word (race) and try again
    local withoutFirst = s:gsub('^%S+%s+', '')
    if withoutFirst ~= s then
        return canonicalize_class(withoutFirst)
    end
    return s
end

-- Bot creation state
M.showCreateDialog = false
M.newBotName = ""
M.selectedClass = 0  -- 0-based for ImGui combo (WAR)
M.selectedRace = 0   -- 0-based for ImGui combo (HUM)
M.selectedGender = 0 -- 0-based for ImGui combo (Male)

-- Available options from the bot creation dialog
M.classes = {
    "WAR", "CLR", "PAL", "RNG", "SHD", "DRU", "MNK", "BRD",
    "ROG", "SHM", "NEC", "WIZ", "MAG", "ENC", "BST", "BER"
}

M.races = {
    "HUM", "BAR", "ERU", "ELF", "HIE", "DEF", "HEF", "DWF",
    "TRL", "OGR", "HFL", "GNM", "IKS", "VAH", "FRG", "DRK"
}

M.genders = {
    "Male", "Female"
}

-- UI state: current class filter (nil = all)
M.classFilter = nil

-- Convert selections to numeric IDs for ^botcreate command
-- Based on EverQuest class IDs
M.classIDs = {
    ["WAR"] = 1, ["CLR"] = 2, ["PAL"] = 3, ["RNG"] = 4,
    ["SHD"] = 5, ["DRU"] = 6, ["MNK"] = 7, ["BRD"] = 8,
    ["ROG"] = 9, ["SHM"] = 10, ["NEC"] = 11, ["WIZ"] = 12,
    ["MAG"] = 13, ["ENC"] = 14, ["BST"] = 15, ["BER"] = 16
}

-- Based on EverQuest race IDs
M.raceIDs = {
    ["HUM"] = 1, ["BAR"] = 2, ["ERU"] = 3, ["ELF"] = 4,
    ["HIE"] = 5, ["DEF"] = 6, ["HEF"] = 7, ["DWF"] = 8,
    ["TRL"] = 9, ["OGR"] = 10, ["HFL"] = 11, ["GNM"] = 12,
    ["IKS"] = 128, ["VAH"] = 130, ["FRG"] = 330, ["DRK"] = 522
}

M.genderIDs = {
    ["Male"] = 0, ["Female"] = 1
}

local function printf(fmt, ...)
    if mq.printf then mq.printf(fmt, ...) else print(string.format(fmt, ...)) end
end

-- Seed RNG once per module load
math.randomseed(os.time())

-- EverQuest-style random name generator
local function generate_random_name()
    local consonants = {'b','c','d','f','g','h','j','k','l','m','n','p','r','s','t','v','w','x','z'}
    local blends = {'br','cr','dr','fr','gr','pr','tr','bl','cl','fl','gl','pl','sl','th','sh','ch','qu','kh','ph'}
    local vowels = {'a','e','i','o','u','ae','ei'}
    local endings = {'or','ar','ir','us','an','en','on','in','el','il','ax','ex','ix','ius','ian','wyn','ryn','thar','dor','nor'}

    local name = ''
    local syllables = math.random(2,3)
    for i=1,syllables do
        if math.random() > 0.3 then
            if math.random() > 0.6 then name = name .. blends[math.random(#blends)]
            else name = name .. consonants[math.random(#consonants)] end
        end
        name = name .. vowels[math.random(#vowels)]
        if i < syllables and math.random() > 0.5 then
            name = name .. consonants[math.random(#consonants)]
        end
    end
    if math.random() > 0.6 then name = name .. endings[math.random(#endings)] end
    name = name:sub(1,1):upper() .. name:sub(2)
    if #name > 12 then name = name:sub(1,12) end
    if #name < 6 then name = name .. endings[math.random(#endings)] end
    return name
end

local function is_bot_spawned(name)
    local s = mq.TLO.Spawn(string.format('= %s', name))
    return s and s.ID and s.ID() and s.ID() > 0
end

local function target_bot(name)
    -- Non-blocking targeting (no mq.delay in ImGui thread)
    local s = mq.TLO.Spawn(string.format('= %s', name))
    if s and s.ID and s.ID() and s.ID() > 0 then
        mq.cmdf('/target id %d', s.ID())
        return true
    end
    mq.cmdf('/target "%s"', name)
    -- Return optimistically; the client will target shortly
    return true
end

local function action_spawn(name)
    mq.cmdf('/say ^spawn %s', name)
end

local function action_invite(name)
    if target_bot(name) then
        mq.cmd('/invite')
    else
        printf('[EmuBot] Could not target %s to invite', name)
    end
end

local function action_camp(name)
    -- Attempt to target first (non-blocking/optimistic)
    target_bot(name)

    -- If we have the global enqueueTask, schedule a short verification with retries
    if _G.enqueueTask then
        local attempts = 0
        local maxAttempts = 8
        local function verify_and_camp()
            attempts = attempts + 1
            local t = mq.TLO.Target
            local hasTarget = t and t() and (t.Name() == name)
            if hasTarget then
                mq.cmd('/say ^botcamp')
                return true
            end
            if attempts >= maxAttempts then
                printf('[EmuBot] Could not verify target for %s to camp', name)
                return true
            end
            _G.enqueueTask(function()
                mq.delay(250)
                verify_and_camp()
            end)
            return true
        end
        _G.enqueueTask(function()
            mq.delay(250)
            verify_and_camp()
        end)
    else
        -- Fallback: best-effort immediate check without blocking the UI
        local t = mq.TLO.Target
        if t and t() and (t.Name() == name) then
            mq.cmd('/say ^botcamp')
        else
            printf('[EmuBot] Could not verify target for %s to camp', name)
        end
    end
end

local function action_create_bot(name, class, race, gender)
    if not name or name == '' then
        printf('[EmuBot] Bot name cannot be empty')
        return false
    end
    
    local classID = M.classIDs[class] or 1
    local raceID = M.raceIDs[race] or 1
    local genderID = M.genderIDs[gender] or 0
    
    local command = string.format('/say ^botcreate %s %d %d %d', name, classID, raceID, genderID)
    printf('[EmuBot] Creating bot: %s', command)
    mq.cmd(command)
    
    -- Schedule a delayed refresh to pick up the new bot
    if _G.enqueueTask then
        _G.enqueueTask(function()
            mq.delay(2000)
            bot_inventory.refreshBotList()
        end)
    else
        -- Fallback: Direct delayed refresh if enqueueTask is not available
        -- Using mq.delay directly would block the UI, so we need to use a different approach
        -- Schedule the refresh via a temporary global function that gets called in the game loop
        _G.EmuBotDelayedRefresh = {
            scheduled = os.time(),
            delay = 2, -- 2 seconds delay
            executed = false
        }
    end
    
    return true
end

function M.draw()
    -- Header controls
    if ImGui.Button('Refresh Bot List##mgmt') then
        bot_inventory.refreshBotList()
    end
    ImGui.SameLine()
    if ImGui.Button('Create New Bot##mgmt') then
        M.showCreateDialog = true
    end
    if ImGui.IsItemHovered() then
        ImGui.SetTooltip('Open bot creation dialog to create a new bot with ^botcreate')
    end
    ImGui.SameLine()
    if ImGui.Button('Spawn All##mgmt') then
        local bots = bot_inventory.getAllBots() or {}
        for _, name in ipairs(bots) do
            action_spawn(name)
        end
    end
    ImGui.SameLine()
    if ImGui.Button('Invite All##mgmt') then
        local bots = bot_inventory.getAllBots() or {}
        for _, name in ipairs(bots) do
            action_invite(name)
        end
    end
    ImGui.SameLine()
    if ImGui.Button('Camp All##mgmt') then
        local bots = bot_inventory.getAllBots() or {}
        for _, name in ipairs(bots) do
            action_camp(name)
        end
    end

    ImGui.Separator()

    local bots = bot_inventory.getAllBots() or {}
    -- Note: We continue even if bots list is empty, to show the create panel

    -- Build class counts from captured bot list metadata
    local classCounts = {}
    local totalBots = 0
    local filteredBots = {}
    for _, name in ipairs(bots) do
        local meta = bot_inventory and bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[name]
        local rawClass = meta and meta.Class and tostring(meta.Class) or nil
        local cls = canonicalize_class(rawClass or '') or 'Unknown'
        classCounts[cls] = (classCounts[cls] or 0) + 1
        totalBots = totalBots + 1
        if (not M.classFilter) or (cls == M.classFilter) then
            table.insert(filteredBots, name)
        end
    end
    -- Alphabetized class list for display (include all, even zero counts)
    local classList = {}
    for _, cname in ipairs(CLASS_NAMES) do table.insert(classList, cname) end
    table.sort(classList)

    -- Two-pane layout: left (class counts), right (table)
    local availW = ImGui.GetWindowWidth() or 800
    local style = ImGui.GetStyle()
    local rowH = (ImGui.GetTextLineHeight and ImGui.GetTextLineHeight() or 18) + ((style and style.ItemSpacing and style.ItemSpacing.y) or 4)
    local headerH = (ImGui.GetTextLineHeight and ImGui.GetTextLineHeight() or 18) * 1.8
    local rows = #filteredBots
    local targetH = math.min(420, math.max(180, headerH + rowH * rows + 20))

    local leftW = 200
    local gap = 10
    local rightW = math.max(520, math.min(820, availW - leftW - gap - 20))

    -- Left pane: class counts (aligned two-column table)
    if ImGui.BeginChild('##BotMgmtClasses', leftW, 410, ImGuiChildFlags.Border) then
        ImGui.Text('Classes')
        ImGui.Separator()
        local shown = 0
        if ImGui.BeginTable('BotMgmtClassCounts', 2, ImGuiTableFlags.RowBg + ImGuiTableFlags.SizingFixedFit) then
            ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthStretch)
            ImGui.TableSetupColumn('#', ImGuiTableColumnFlags.WidthFixed, 36)
            -- 'All' row to clear filter
            ImGui.TableNextRow()
            ImGui.TableNextColumn();
            local allSel = (M.classFilter == nil)
            if ImGui.Selectable('All', allSel, ImGuiSelectableFlags.SpanAllColumns) then
                M.classFilter = nil
            end
            ImGui.TableNextColumn(); ImGui.Text(string.format('%d', totalBots))
            shown = shown + 1
            -- Class rows
            for _, cname in ipairs(classList) do
                local cnt = classCounts[cname] or 0
                ImGui.TableNextRow()
                ImGui.TableNextColumn();
                local isSel = (M.classFilter == cname)
                if ImGui.Selectable(cname, isSel, ImGuiSelectableFlags.SpanAllColumns) then
                    M.classFilter = cname
                end
                ImGui.TableNextColumn(); ImGui.Text(string.format('%d', cnt))
                shown = shown + 1
            end
            ImGui.EndTable()
        end
        ImGui.Separator()
        if ImGui.BeginTable('BotMgmtClassTotal', 2, ImGuiTableFlags.SizingFixedFit) then
            ImGui.TableSetupColumn('Label', ImGuiTableColumnFlags.WidthStretch)
            ImGui.TableSetupColumn('Val', ImGuiTableColumnFlags.WidthFixed, 36)
            ImGui.TableNextRow()
            ImGui.TableNextColumn(); ImGui.Text('Total')
            ImGui.TableNextColumn(); ImGui.Text(string.format('%d', totalBots))
            ImGui.EndTable()
        end
    end
    ImGui.EndChild()

    ImGui.SameLine()

    -- Right pane: contained table
    if ImGui.BeginChild('##BotMgmtContainer', 400, 410, ImGuiChildFlags.Border) then
        if ImGui.BeginTable('BotManagementTable', 3,
                ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.SizingFixedFit + ImGuiTableFlags.Sortable) then
            ImGui.TableSetupColumn('Bot', ImGuiTableColumnFlags.WidthStretch)
            ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 110)
            ImGui.TableSetupColumn('Actions', ImGuiTableColumnFlags.WidthStretch)
            ImGui.TableHeadersRow()

            applyTableSort(filteredBots, ImGui.TableGetSortSpecs(), {
                [1] = function(row) return row or '' end,
                [2] = function(row) return canonicalize_class((bot_inventory.bot_list_capture_set[row] and bot_inventory.bot_list_capture_set[row].Class) or '') or '' end,
            })

            for _, name in ipairs(filteredBots) do
                ImGui.TableNextRow()
                ImGui.PushID('mgmt_' .. name)

                -- Bot name (colored by spawn state, selectable targets)
                ImGui.TableNextColumn()
                if is_bot_spawned(name) then
                    ImGui.PushStyleColor(ImGuiCol.Text, 0.2, 0.8, 0.2, 1.0)
                else
                    ImGui.PushStyleColor(ImGuiCol.Text, 0.8, 0.2, 0.2, 1.0)
                end
                if ImGui.Selectable(name, false) then
                    target_bot(name)
                end
                ImGui.PopStyleColor(1)

                -- Class (from captured bot list meta)
                ImGui.TableNextColumn()
                do
                    local cls = nil
                    local meta = bot_inventory and bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[name]
                    if meta then
                        local rawClass = meta.Class and tostring(meta.Class) or nil
                        if rawClass and rawClass ~= '' then
                            cls = canonicalize_class(rawClass)
                        end
                    end
                    ImGui.Text(cls or '-')
                end

                -- Actions
                ImGui.TableNextColumn()
                if ImGui.SmallButton('Spawn') then action_spawn(name) end
                ImGui.SameLine()
                if ImGui.SmallButton('Invite') then action_invite(name) end
                ImGui.SameLine()
                if ImGui.SmallButton('Camp') then action_camp(name) end

                ImGui.PopID()
            end

            ImGui.EndTable()
        end
    end
    ImGui.EndChild()
    
    ImGui.SameLine()
    
    -- Right pane: Create New Bot
if ImGui.BeginChild('##BotMgmtCreate', 300, 410, ImGuiChildFlags.Border) then
        ImGui.Text('Create New Bot')
        ImGui.Separator()
        
        -- Name with random generator
        ImGui.Text('Name:')
        ImGui.PushItemWidth(200)  -- Fixed width for input leaving room for button
        M.newBotName = ImGui.InputText('##BotName', M.newBotName or '')
        ImGui.PopItemWidth()
        ImGui.SameLine()
        if ImGui.Button('Random ##RandomName', 80, 0) then
            M.newBotName = generate_random_name()
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Generate random fantasy name')
        end
        
        ImGui.Spacing()
        
        -- Class (blank until selected; filters after race selection)
        ImGui.Text('Class:')
        do
            ImGui.PushItemWidth(-1)
            local raceIndex = tonumber(M.selectedRace or 0) or 0
            local source = {}
            if raceIndex > 0 then
                local raceCode = M.races[raceIndex]
                source = race_class_utils.allowed_classes_for_race(raceCode)
            else
                source = M.classes
            end
            -- Build sorted view with placeholder first
            local sorted = {}
            for _, v in ipairs(source or {}) do table.insert(sorted, v) end
            table.sort(sorted, function(a,b) return tostring(a) < tostring(b) end)
            local view = {'-- Select Class --'}
            for _, v in ipairs(sorted) do table.insert(view, v) end
            -- Current index based on existing selected class code
            local currentCode = (tonumber(M.selectedClass or 0) or 0) > 0 and M.classes[M.selectedClass] or nil
            local currentIndex = 1
            if currentCode then
                for i, code in ipairs(sorted) do if code == currentCode then currentIndex = i + 1; break end end
            end
            local newIndex, changed = ImGui.Combo('##ClassCombo', currentIndex, view, #view)
            if changed and newIndex then
                if newIndex == 1 then
                    M.selectedClass = 0
                else
                    local chosen = sorted[newIndex - 1]
                    for i, code in ipairs(M.classes) do if code == chosen then M.selectedClass = i; break end end
                    -- If a race is selected but now invalid with this class, clear race
                    if (tonumber(M.selectedRace or 0) or 0) > 0 then
                        local raceCode = M.races[M.selectedRace]
                        if not race_class_utils.is_valid_combo(raceCode, chosen) then
                            M.selectedRace = 0
                        end
                    end
                end
            end
            ImGui.PopItemWidth()
        end
        
        ImGui.Spacing()
        
        -- Race (blank until selected; filters after class selection)
        ImGui.Text('Race:')
        do
            ImGui.PushItemWidth(-1)
            local classIndex = tonumber(M.selectedClass or 0) or 0
            local source = {}
            if classIndex > 0 then
                local classCode = M.classes[classIndex]
                source = race_class_utils.allowed_races_for_class(classCode)
            else
                source = M.races
            end
            local sorted = {}
            for _, v in ipairs(source or {}) do table.insert(sorted, v) end
            table.sort(sorted, function(a,b)
                local A = race_class_utils.RACE_NAMES[a] or a
                local B = race_class_utils.RACE_NAMES[b] or b
                return tostring(A) < tostring(B)
            end)
            local view = {'-- Select Race --'}
            for _, v in ipairs(sorted) do table.insert(view, v) end
            local currentCode = (tonumber(M.selectedRace or 0) or 0) > 0 and M.races[M.selectedRace] or nil
            local currentIndex = 1
            if currentCode then
                for i, code in ipairs(sorted) do if code == currentCode then currentIndex = i + 1; break end end
            end
            local newIndex, changed = ImGui.Combo('##RaceCombo', currentIndex, view, #view)
            if changed and newIndex then
                if newIndex == 1 then
                    M.selectedRace = 0
                else
                    local chosen = sorted[newIndex - 1]
                    for i, code in ipairs(M.races) do if code == chosen then M.selectedRace = i; break end end
                    -- If a class is selected but now invalid with this race, clear class
                    if (tonumber(M.selectedClass or 0) or 0) > 0 then
                        local classCode = M.classes[M.selectedClass]
                        if not race_class_utils.is_valid_combo(chosen, classCode) then
                            M.selectedClass = 0
                        end
                    end
                end
            end
            ImGui.PopItemWidth()
        end
        
        ImGui.Spacing()
        
        -- Gender
        ImGui.Text('Gender:')
        ImGui.PushItemWidth(-1)
        M.selectedGender = ImGui.Combo('##GenderCombo', M.selectedGender, M.genders, #M.genders)
        ImGui.PopItemWidth()
        
        ImGui.Spacing()
        ImGui.Separator()
        
        -- Preview the command
        if M.newBotName and M.newBotName ~= '' then
            local selectedClassName = M.classes[M.selectedClass] or 'WAR'
            local selectedRaceName = M.races[M.selectedRace] or 'HUM'
            local selectedGenderName = M.genders[M.selectedGender] or 'Male'
            
            local classID = M.classIDs[selectedClassName] or 1
            local raceID = M.raceIDs[selectedRaceName] or 1
            local genderID = M.genderIDs[selectedGenderName] or 0
            
            local previewCommand = string.format('/say ^botcreate %s %d %d %d', 
                M.newBotName, classID, raceID, genderID)
            
            ImGui.TextColored(0.7, 0.7, 0.7, 1.0, 'Command:')
            ImGui.TextWrapped(previewCommand)
            ImGui.Spacing()
        end
        
        -- Buttons
        local canCreate = M.newBotName and M.newBotName ~= ''
        -- Also require explicit selections and validate only when both are chosen
        do
            local raceIndex = tonumber(M.selectedRace or 0) or 0
            local classIndex = tonumber(M.selectedClass or 0) or 0
            if raceIndex <= 0 or classIndex <= 0 then
                canCreate = false
            else
                local raceCode = M.races[raceIndex]
                local classCode = M.classes[classIndex]
                if not race_class_utils.is_valid_combo(raceCode, classCode) then
                    canCreate = false
                end
            end
        end
        
        if not canCreate then
            ImGui.PushStyleColor(ImGuiCol.Button, 0.5, 0.5, 0.5, 0.5)
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.5, 0.5, 0.5, 0.5)
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.5, 0.5, 0.5, 0.5)
        end
        
        if ImGui.Button('Create Bot', -1, 0) then
            if canCreate then
                local selectedClassName = M.classes[M.selectedClass] or 'WAR'
                local selectedRaceName = M.races[M.selectedRace] or 'HUM'
                local selectedGenderName = M.genders[M.selectedGender] or 'Male'
                
                local success = action_create_bot(M.newBotName, selectedClassName, selectedRaceName, selectedGenderName)
                if success then
                    -- Reset form
                    M.newBotName = ''
                    M.selectedClass = 0
                    M.selectedRace = 0
                    M.selectedGender = 0
                end
            end
        end
        
        if not canCreate then
            ImGui.PopStyleColor(3)
        end
        
        if ImGui.IsItemHovered() and not canCreate then
            local raceIndex = tonumber(M.selectedRace or 0) or 0
            local classIndex = tonumber(M.selectedClass or 0) or 0
            local reason = 'Please enter a bot name'
            if M.newBotName and M.newBotName ~= '' then
                if raceIndex <= 0 or classIndex <= 0 then
                    reason = 'Select a race and class'
                else
                    local raceCode = M.races[raceIndex]
                    local classCode = M.classes[classIndex]
                    if not race_class_utils.is_valid_combo(raceCode, classCode) then
                        reason = string.format('Invalid combo: %s + %s', raceCode, classCode)
                    end
                end
            end
            ImGui.SetTooltip(reason)
        end
        
        if ImGui.Button('Clear', -1, 0) then
            M.newBotName = ''
            M.selectedClass = 0
            M.selectedRace = 0
            M.selectedGender = 0
        end
    end
    ImGui.EndChild()
end

return M
