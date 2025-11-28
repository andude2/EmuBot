-- EmuBot Raid Manager
-- GUI to build raid layouts from saved groups and apply to the in-game Raid Window

local mq = require('mq')
local ImGui = require('ImGui')
local db = require('modules.db')
local bot_inventory = require('modules.bot_inventory')
local connected_players = require('modules.connected_players')
local json = require('dkjson')

local M = {}

-- State
M.selectedGroupIds = {}
M.desiredLayout = {}
M.includeBench = true
M.statusText = ""
M._meSeeded = false
-- UI: number of raid groups to display in the layout grid (1-12)
M.groupsToDisplay = 12
-- Display preference: show class instead of name
M.showClassNames = false

function M.set_show_class_names(v)
    M.showClassNames = v and true or false
end

-- forward declarations
local inDesired
local isSpawned
local inviteToRaid

-- deferred execution hook (set by init.lua)
M._enqueue = nil
function M.set_enqueue(fn)
    M._enqueue = fn
end

local function printf(fmt, ...)
    if mq.printf then mq.printf(fmt, ...) else print(string.format(fmt, ...)) end
end

local function initLayout()
    for g = 1, 12 do M.desiredLayout[g] = M.desiredLayout[g] or {} end
end

local function getBotOwner(name)
    if not name or name == '' then return nil end
    if bot_inventory and bot_inventory.getBotOwner then
        return bot_inventory.getBotOwner(name)
    end
    return nil
end

local function isLocalBot(name)
    if not bot_inventory or not bot_inventory.isBotOwnedLocally then return true end
    return bot_inventory.isBotOwnedLocally(name)
end

local function isOwnerInRaid(owner)
    if not owner or owner == '' then return false end
    local raid = mq.TLO.Raid
    if not raid or not raid.Members or raid.Members() == 0 then return false end
    local count = raid.Members()
    for i = 1, count do
        local member = raid.Member(i)
        if member and member.Name and member.Name() and member.Name():lower() == owner:lower() then
            return true
        end
    end
    return false
end

local function ensurePeerInRaid(owner)
    if not owner or owner == '' then return false end
    if isOwnerInRaid(owner) then return true end
    inviteToRaid(owner)
    mq.delay(5000, function() return isOwnerInRaid(owner) end)
    return isOwnerInRaid(owner)
end

local function waitForSpawnByName(name, timeoutMs)
    local timeout = (timeoutMs or 8000) / 1000
    local deadline = os.clock() + timeout
    repeat
        if isSpawned(name) then return true end
        mq.delay(200)
    until os.clock() >= deadline
    return isSpawned(name)
end

local function partitionBots(botList)
    local locals = {}
    local remote = {}
    for _, name in ipairs(botList) do
        if name and name ~= '' then
            if isLocalBot(name) then
                table.insert(locals, name)
            else
                local owner = getBotOwner(name)
                if owner and owner ~= '' then
                    remote[owner] = remote[owner] or {}
                    table.insert(remote[owner], name)
                else
                    table.insert(locals, name)
                end
            end
        end
    end
    return locals, remote
end

local function inviteRemoteBots(remoteMap)
    if not remoteMap then return 0 end
    local totalInvited = 0
    for owner, bots in pairs(remoteMap) do
        if owner and connected_players and connected_players.is_connected and connected_players.is_connected(owner) then
            if ensurePeerInRaid(owner) then
                for _, botName in ipairs(bots) do
                    if connected_players.request_remote_spawn then
                        connected_players.request_remote_spawn(owner, {botName})
                    end
                    waitForSpawnByName(botName, 12000)
                    if isSpawned(botName) then
                        inviteToRaid(botName)
                        mq.delay(100)
                        totalInvited = totalInvited + 1
                    else
                        printf('[RaidManager] Timed out waiting for %s to spawn for raid.', botName)
                    end
                end
            else
                printf('[RaidManager] Peer %s is not in the raid. Invite them first to include their bots.', owner)
            end
        else
            printf('[RaidManager] Peer %s not connected; skipping remote bots.', owner or 'unknown')
        end
    end
    return totalInvited
end

local function getMyName()
    local me = nil
    if mq and mq.TLO and mq.TLO.Me then
        local ok, val = pcall(function() return mq.TLO.Me.CleanName() or mq.TLO.Me.Name() end)
        if ok then me = val end
    end
    if me and me ~= '' then return tostring(me) end
    return nil
end

local function seedMeDefault()
    if M._meSeeded then return end
    local me = getMyName()
    if not me then return end
    if not inDesired(me) and not M.desiredLayout[1][1] then
        M.desiredLayout[1][1] = me
        M._meSeeded = true
        M.statusText = string.format('Defaulted %s to Group 1, Slot 1.', me)
    else
        M._meSeeded = true
    end
end

-- Persistence (save/load raid layouts)
local function layouts_path()
    return string.format('%s/raid_layouts.json', mq.configDir)
end

M._savedLayouts = {}

function M.load_saved_layouts()
    local p = layouts_path()
    local f = io.open(p, 'r')
    if not f then
        M._savedLayouts = {}; return
    end
    local content = f:read('*a') or ''
    f:close()
    local data = json.decode(content) or {}
    M._savedLayouts = data
end

local function deepcopy(tbl)
    if type(tbl) ~= 'table' then return tbl end
    local t = {}
    for k, v in pairs(tbl) do t[k] = deepcopy(v) end
    return t
end

function M.save_current_layout(name)
    if not name or name == '' then
        M.statusText = 'Enter a layout name.'; return false
    end
    -- normalize layout to 12x6 structure
    local out = {}
    for g = 1, 12 do
        out[g] = {}
        for s = 1, 6 do out[g][s] = M.desiredLayout[g] and M.desiredLayout[g][s] or nil end
    end
    M._savedLayouts[name] = out
    local p = layouts_path()
    local f = io.open(p, 'w')
    if not f then
        M.statusText = 'Failed to open raid_layouts.json for write'; return false
    end
    f:write(json.encode(M._savedLayouts, { indent = true }))
    f:close()
    M.statusText = string.format('Saved layout "%s"', name)
    return true
end

function M.load_layout(name)
    local layout = M._savedLayouts[name]
    if not layout then
        M.statusText = 'Layout not found'; return false
    end
    M.desiredLayout = deepcopy(layout)
    M.statusText = string.format('Loaded layout "%s"', name)
    return true
end

function M.delete_layout(name)
    if not M._savedLayouts[name] then return end
    M._savedLayouts[name] = nil
    local p = layouts_path()
    local f = io.open(p, 'w')
    if f then
        f:write(json.encode(M._savedLayouts, { indent = true })); f:close()
    end
    M.statusText = string.format('Deleted layout "%s"', name)
end

local function listSelectedBots()
    local names = {}
    local seen = {}
    local groups = db.get_groups_with_members() or {}
    for _, g in ipairs(groups) do
        if M.selectedGroupIds[g.id] then
            for _, m in ipairs(g.members or {}) do
                if m.bot_name and not seen[m.bot_name] then
                    table.insert(names, m.bot_name)
                    seen[m.bot_name] = true
                end
            end
        end
    end
    table.sort(names, function(a, b) return a:lower() < b:lower() end)
    return names
end

function inDesired(name)
    for g = 1, 12 do
        for slot = 1, 6 do
            if M.desiredLayout[g][slot] == name then return true end
        end
    end
    return false
end

local function benchList()
    local bench = {}
    local all = listSelectedBots()
    for _, n in ipairs(all) do
        if not inDesired(n) then table.insert(bench, n) end
    end
    return bench
end

-- Bots available to place from the full bot list (not limited to selected groups)
local function unassignedAllBots()
    local all = {}
    if bot_inventory and bot_inventory.getAllBots then
        all = bot_inventory.getAllBots() or {}
    end
    table.sort(all, function(a, b) return tostring(a):lower() < tostring(b):lower() end)
    local res = {}
    for _, name in ipairs(all) do
        if not inDesired(name) then table.insert(res, name) end
    end
    return res
end

-- Class abbreviation helper (mirrors logic from inventory viewer)
local function get_bot_class_abbrev(name)
    local meta = bot_inventory and bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[name]
    local cls = meta and meta.Class or nil
    if not cls or cls == '' then return 'UNK' end
    local up = tostring(cls):upper()
    local map = {
        WAR='WAR', WARRIOR='WAR',
        CLR='CLR', CLERIC='CLR',
        PAL='PAL', PALADIN='PAL',
        RNG='RNG', RANGER='RNG',
        SHD='SHD', ['SHADOWKNIGHT']='SHD', SHADOWKNIGHT='SHD', SK='SHD',
        DRU='DRU', DRUID='DRU',
        MNK='MNK', MONK='MNK',
        BRD='BRD', BARD='BRD',
        ROG='ROG', ROGUE='ROG',
        SHM='SHM', SHAMAN='SHM',
        NEC='NEC', NECROMANCER='NEC',
        WIZ='WIZ', WIZARD='WIZ',
        MAG='MAG', MAGICIAN='MAG',
        ENC='ENC', ENCHANTER='ENC',
        BST='BST', BEAST='BST', BEASTLORD='BST', BL='BST',
        BER='BER', BERSERKER='BER',
    }
    if map[up] then return map[up] end
    for key, val in pairs(map) do if up:find(key) then return val end end
    return 'UNK'
end

local function display_label(name)
    if M.showClassNames then
        return get_bot_class_abbrev(name)
    end
    return name
end

local function clearLayout()
    for g = 1, 12 do M.desiredLayout[g] = {} end
end

local function autofill()
    clearLayout()
    local me = getMyName()
    local gi, si = 1, 1
    if me then
        M.desiredLayout[1][1] = me
        si = 2
    end
    local all = listSelectedBots()
    for _, name in ipairs(all) do
        if not me or name ~= me then
            M.desiredLayout[gi][si] = name
            si = si + 1
            if si > 6 then
                gi = gi + 1; si = 1
            end
            if gi > 12 then break end
        end
    end
end

-- RaidWindow helpers
local function openRaidWindow()
    if not mq.TLO.Window('RaidWindow').Open() then
        mq.TLO.Window('RaidWindow').DoOpen()
        mq.delay(300, function() return mq.TLO.Window('RaidWindow').Open() end)
    end
end

local function raidUnlock()
    openRaidWindow()
    mq.cmdf('/notify RaidWindow RAID_UnLockButton LeftMouseUp')
    mq.delay(250)
end

local function raidLock()
    openRaidWindow()
    mq.cmdf('/notify RaidWindow RAID_LockButton LeftMouseUp')
    mq.delay(250)
end

local function notInGroupIndexByName(name)
    local child = mq.TLO.Window('RaidWindow').Child('RAID_NotInGroupPlayerList')
    if not child or child() == 0 then return nil end
    local count = child.Items() or 0
    for i = 1, count do
        local cell = child.List(i, 2)()
        if cell and cell:lower() == name:lower() then
            return i
        end
    end
    return nil
end

local function assignFromNotInGroup(name, groupNum)
    local idx = notInGroupIndexByName(name)
    if not idx then return false, 'not found in pending list' end
    mq.cmdf('/notify RaidWindow RAID_NotInGroupPlayerList ListSelect %d', idx)
    mq.delay(50)
    mq.cmdf('/notify RaidWindow RAID_Group%dButton LeftMouseUp', tonumber(groupNum) or 1)
    mq.delay(100)
    return true
end

isSpawned = function(name)
    local s = mq.TLO.Spawn(string.format('=%s', name))
    return s and s() and s.ID() and s.ID() > 0
end

local function spawnIfNeeded(name)
    if isSpawned(name) then return true end
    mq.cmdf('/say ^spawn %s', name)
    mq.delay(500, function() return isSpawned(name) end)
    return isSpawned(name)
end

inviteToRaid = function(name)
    mq.cmdf('/raidinvite %s', name)
    if M.live_pc_mode then
        -- If a confirmation dialog appears, click Yes.
        mq.delay(500, function() return (mq.TLO.Window('ConfirmationDialogBox') and mq.TLO.Window('ConfirmationDialogBox').Open()) end)
        if mq.TLO.Window('ConfirmationDialogBox') and mq.TLO.Window('ConfirmationDialogBox').Open() then
            mq.cmd('/notify ConfirmationDialogBox CD_Yes_Button leftmouseup')
            mq.delay(150)
        end
    end
end

-- Public actions
local function getLayoutBotList()
    local set = {}
    local list = {}
    for g = 1, 12 do
        for s = 1, 6 do
            local n = M.desiredLayout[g] and M.desiredLayout[g][s]
            if n and n ~= '' and not set[n] then
                set[n] = true
                table.insert(list, n)
            end
        end
    end
    return list
end

function M.formRaidForSelected()
    local bots = listSelectedBots()
    if #bots == 0 then
        M.statusText = 'No bots selected.'; return
    end
    local localBots, remoteBots = partitionBots(bots)
    openRaidWindow(); raidUnlock()
    for _, n in ipairs(localBots) do
        spawnIfNeeded(n)
        inviteToRaid(n)
        mq.delay(100)
    end
    local remoteInvited = inviteRemoteBots(remoteBots)
    raidLock()
    M.statusText = string.format('Invited %d local and %d remote bot(s) to raid.', #localBots, remoteInvited)
end

function M.applyLayout()
    openRaidWindow(); raidLock()
    local totalAssigned = 0
    for g = 1, 12 do
        for slot = 1, 6 do
            local name = M.desiredLayout[g][slot]
            if name and name ~= '' then
                local ok = assignFromNotInGroup(name, g)
                if ok then totalAssigned = totalAssigned + 1 end
            end
        end
    end
    raidUnlock()
    M.statusText = string.format('Applied layout to %d bot(s) from Not In Group.', totalAssigned)
end

-- Combined: spawn/invite all bots present in the layout, then arrange into groups
function M.formRaidFromLayout()
    local bots = getLayoutBotList()
    if #bots == 0 then
        M.statusText = 'No bots in layout to invite.'; return
    end
    local localBots, remoteBots = partitionBots(bots)
    openRaidWindow(); raidUnlock()
    -- spawn and invite quickly
    for _, n in ipairs(localBots) do
        if n ~= getMyName() then
            spawnIfNeeded(n)
            inviteToRaid(n)
            mq.delay(50)
        end
    end
    local remoteInvited = inviteRemoteBots(remoteBots)
    raidLock()

    -- arrange with retries to allow NotInGroup to populate (Raid must be LOCKED for move buttons to work)
    openRaidWindow(); raidLock()
    local totalAssigned = 0
    for g = 1, 12 do
        for s = 1, 6 do
            local name = M.desiredLayout[g][s]
            if name and name ~= '' then
                local attempts = 0
                local assigned = false
                while attempts < 20 and not assigned do
                    local ok = assignFromNotInGroup(name, g)
                    if ok then
                        assigned = true
                        totalAssigned = totalAssigned + 1
                    else
                        mq.delay(150)
                        attempts = attempts + 1
                    end
                end
            end
        end
    end
    raidUnlock()
    M.statusText = string.format('Invited %d local, %d remote and arranged %d bot(s).', #localBots, remoteInvited, totalAssigned)
end

-- UI
function M.draw_tab()
    initLayout()
    seedMeDefault()
    -- Top controls
    if ImGui.Button('Refresh Groups') then end
    ImGui.SameLine()
    if ImGui.Button('Auto-Fill From Selected Groups') then autofill() end
    ImGui.SameLine()
    if ImGui.Button('Clear Layout') then clearLayout() end

    ImGui.Separator()

    local availW = ImGui.GetWindowContentRegionWidth()
    local leftW = math.floor(availW * 0.33)
    ImGui.BeginChild('RaidLeftPane', ImVec2(leftW, 420), true)
    ImGui.Text('Select Groups:')
    local groups = db.get_groups_with_members() or {}
    for _, g in ipairs(groups) do
        local checked = M.selectedGroupIds[g.id] and true or false
        local newChecked = ImGui.Checkbox(
        string.format('%s (%d)', g.name or ('Group ' .. tostring(g.id)), (g.members and #g.members or 0)), checked)
        M.selectedGroupIds[g.id] = newChecked or nil
    end

    ImGui.Separator()
    ImGui.Text('All Bots:')
    local allBots = {}
    if bot_inventory and bot_inventory.getAllBots then
        allBots = bot_inventory.getAllBots() or {}
    end
    table.sort(allBots, function(a, b) return tostring(a):lower() < tostring(b):lower() end)
    if ImGui.BeginTable('AllBotsTable', 3, ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable) then
        ImGui.TableSetupColumn('Bot Name', ImGuiTableColumnFlags.WidthStretch)
        ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 120)
        ImGui.TableSetupColumn('Add', ImGuiTableColumnFlags.WidthFixed, 70)
        ImGui.TableHeadersRow()
        for _, name in ipairs(allBots) do
            ImGui.TableNextRow()
            ImGui.TableNextColumn(); ImGui.Text(tostring(name))
            ImGui.TableNextColumn();
            local clsMeta = bot_inventory and bot_inventory.bot_list_capture_set and
            bot_inventory.bot_list_capture_set[name]
            local rawClass = clsMeta and clsMeta.Class or ''
            local up = tostring(rawClass or ''):upper()
            local fullMap = {
                WAR = 'Warrior',
                WARRIOR = 'Warrior',
                CLR = 'Cleric',
                CLERIC = 'Cleric',
                PAL = 'Paladin',
                PALADIN = 'Paladin',
                RNG = 'Ranger',
                RANGER = 'Ranger',
                SHD = 'Shadow Knight',
                ['SHADOW KNIGHT'] = 'Shadow Knight',
                SHADOWKNIGHT = 'Shadow Knight',
                SK = 'Shadow Knight',
                DRU = 'Druid',
                DRUID = 'Druid',
                MNK = 'Monk',
                MONK = 'Monk',
                BRD = 'Bard',
                BARD = 'Bard',
                ROG = 'Rogue',
                ROGUE = 'Rogue',
                SHM = 'Shaman',
                SHAMAN = 'Shaman',
                NEC = 'Necromancer',
                NECROMANCER = 'Necromancer',
                WIZ = 'Wizard',
                WIZARD = 'Wizard',
                MAG = 'Magician',
                MAGICIAN = 'Magician',
                ENC = 'Enchanter',
                ENCHANTER = 'Enchanter',
                BST = 'Beastlord',
                BEAST = 'Beastlord',
                BEASTLORD = 'Beastlord',
                BL = 'Beastlord',
                BER = 'Berserker',
                BERSERKER = 'Berserker',
            }
            local full = fullMap[up]
            if not full then
                for key, val in pairs(fullMap) do if up:find(key) then
                        full = val; break
                    end end
            end
            ImGui.Text(full or 'Unknown')

            ImGui.TableNextColumn()
            ImGui.PushID(name)
            if inDesired(name) then
                ImGui.TextDisabled('Added')
            else
                if ImGui.SmallButton('Add') then
                    -- place into the next available empty slot in the layout
                    local placed = false
                    for g = 1, 12 do
                        for slot = 1, 6 do
                            if not M.desiredLayout[g][slot] then
                                M.desiredLayout[g][slot] = name
                                placed = true
                                break
                            end
                        end
                        if placed then break end
                    end
                    if not placed then
                        M.statusText = 'Raid layout is full (72 slots).'
                    else
                        M.statusText = string.format('Added %s to layout.', name)
                    end
                end
            end
            ImGui.PopID()
        end
        ImGui.EndTable()
    end

    if ImGui.Button('Invite Selected To Raid') then
        if M._enqueue then M._enqueue(M.formRaidForSelected) else M.formRaidForSelected() end
    end
    ImGui.EndChild()

    ImGui.SameLine()

    -- Right pane: raid grid
    ImGui.BeginChild('RaidRightPane', ImVec2(0, 420), true)
    -- Save/Load controls
    M._saveName = M._saveName or ''
    M._saveName = select(1, ImGui.InputTextWithHint('##raidlayoutname', 'Add New Layout', M._saveName))
    ImGui.SameLine()
    if ImGui.SmallButton('Save') then M.save_current_layout(M._saveName) end
    ImGui.SameLine()
    if ImGui.SmallButton('Reload List') then M.load_saved_layouts() end

    local names = {}
    for k, _ in pairs(M._savedLayouts or {}) do table.insert(names, k) end
    table.sort(names)
    if ImGui.BeginTable('SavedLayouts', 3, ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable) then
        ImGui.TableSetupColumn('Name', ImGuiTableColumnFlags.WidthStretch)
        ImGui.TableSetupColumn('Load', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('Delete', ImGuiTableColumnFlags.WidthFixed, 70)
        ImGui.TableHeadersRow()
        for _, n in ipairs(names) do
            ImGui.TableNextRow()
            ImGui.TableNextColumn(); ImGui.Text(display_label(n))
            ImGui.TableNextColumn(); if ImGui.SmallButton('Load##' .. n) then M.load_layout(n) end
            ImGui.TableNextColumn(); if ImGui.SmallButton('Delete##' .. n) then M.delete_layout(n) end
        end
        ImGui.EndTable()
    end

    ImGui.Separator()
    if ImGui.Button('Apply') then
        if M._enqueue then M._enqueue(M.applyLayout) else M.applyLayout() end
    end
    ImGui.SameLine()
    if ImGui.Button('Form Raid') then
        if M._enqueue then M._enqueue(M.formRaidFromLayout) else M.formRaidFromLayout() end
    end
    ImGui.SameLine()
    if ImGui.Button('Disband + Camp Bots') then
        if M._enqueue then
            M._enqueue(function()
                mq.cmd('/raiddisband')
                mq.delay(200)
                mq.cmd('/say ^botcamp all')
            end)
        else
            mq.cmd('/raiddisband')
            mq.cmd('/say ^botcamp all')
        end
        M.statusText = 'Raid disband + camp all triggered.'
    end
    ImGui.SameLine()
    ImGui.Text('# of Groups:')
    ImGui.SameLine()
    -- Dropdown (combo) 1-12 instead of slider (Combo is 1-based)
    M._groupsOptions = M._groupsOptions or {'1','2','3','4','5','6','7','8','9','10','11','12'}
    local currentIdx = M.groupsToDisplay or 12 -- 1-based
    ImGui.PushItemWidth(60)
    local newIdx, changed = ImGui.Combo('##RaidGroupsToDisplay', currentIdx, M._groupsOptions, #M._groupsOptions)
    ImGui.PopItemWidth()
    if changed and newIdx then
        M.groupsToDisplay = math.max(1, math.min(12, newIdx))
    end
    ImGui.Text('Raid Layout')
    ImGui.Separator()

    local cols = 4
    local totalGroups = math.max(1, math.min(12, M.groupsToDisplay or 12))
    if ImGui.BeginTable('RaidGrid', cols, ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable) then
        local rows = math.ceil(totalGroups / cols)
        for row = 0, rows-1 do
            ImGui.TableNextRow()
            for col = 1, cols do
                ImGui.TableNextColumn()
                local g = row * cols + col
                if g > totalGroups then
                    -- empty cell for alignment
                    ImGui.Dummy(0, 0)
                else
                ImGui.PushID('raid_group_' .. tostring(g))
                ImGui.Text(string.format('Group %d', g))
                if ImGui.BeginTable('G' .. tostring(g), 2, ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.SizingFixedFit) then
                    ImGui.TableSetupColumn('#', ImGuiTableColumnFlags.WidthFixed, 18)
                    ImGui.TableSetupColumn('Member', ImGuiTableColumnFlags.WidthStretch)
                    ImGui.TableHeadersRow()
                    for slot = 1, 6 do
                        ImGui.PushID(slot)
                        ImGui.TableNextRow()
                        ImGui.TableNextColumn(); ImGui.Text(tostring(slot))
                        ImGui.TableNextColumn()
                        local current = M.desiredLayout[g][slot]
                        if current then
                            if ImGui.SmallButton(display_label(current) .. '##rm') then
                                -- remove: clear this slot (send back to bench)
                                M.desiredLayout[g][slot] = nil
                            end
                            if ImGui.IsItemHovered() then ImGui.SetTooltip('Click to remove to bench') end
                        else
                            -- choose from bench popup
                            if ImGui.SmallButton('Add##add') then
                                ImGui.OpenPopup('pick')
                            end
                            if ImGui.BeginPopup('pick') then
                                local avail = unassignedAllBots()
                                if #avail == 0 then
                                    ImGui.Text('No available bots. Refresh bot list?')
                                else
                                    for _, n in ipairs(avail) do
                                        if ImGui.MenuItem(display_label(n)) then
                                            M.desiredLayout[g][slot] = n
                                            ImGui.CloseCurrentPopup()
                                        end
                                    end
                                end
                                ImGui.EndPopup()
                            end
                        end
                        ImGui.PopID()
                    end
                    ImGui.EndTable()
                end
                if ImGui.SmallButton('Clear##grp' .. tostring(g)) then M.desiredLayout[g] = {} end
                ImGui.PopID()
                end
            end
        end
        ImGui.EndTable()
    end

    ImGui.Separator()
    ImGui.EndChild()
end

function M.init()
    initLayout()
    M.load_saved_layouts()
end

function M.handle_remote_spawn_request(botList)
    if not botList or type(botList) ~= 'table' then return end
    for _, name in ipairs(botList) do
        if name and name ~= '' and isLocalBot(name) then
            spawnIfNeeded(name)
        end
    end
end

return M
