-- emubot/modules/upgrade.lua
-- EmuBot Upgrades: determine which bots can use the cursor item and allow swapping

local mq = require('mq')
local bot_inventory = require('modules.bot_inventory')
local applyTableSort = require('modules.ui_table_utils').applyTableSort

local U = {}

U._candidates = {}
U._show_compare = false
U._pending_refresh = {}
U._close_window_on_swap = true

function U.set_close_window_on_swap(value)
    U._close_window_on_swap = value and true or false
end

function U.get_close_window_on_swap()
    return U._close_window_on_swap
end

-- Forward declaration so functions defined earlier can call it safely
local get_cursor_stats
local get_cursor_weapon_stats

local function printf(fmt, ...)
    if mq.printf then mq.printf(fmt, ...) else print(string.format(fmt, ...)) end
end

local slotNames = {
    [0] = 'Charm', [1] = 'Left Ear', [2] = 'Head', [3] = 'Face', [4] = 'Right Ear',
    [5] = 'Neck', [6] = 'Shoulders', [7] = 'Arms', [8] = 'Back', [9] = 'Left Wrist',
    [10] = 'Right Wrist', [11] = 'Range', [12] = 'Hands', [13] = 'Primary', [14] = 'Secondary',
    [15] = 'Left Ring', [16] = 'Right Ring', [17] = 'Chest', [18] = 'Legs', [19] = 'Feet',
    [20] = 'Waist', [21] = 'Power Source', [22] = 'Ammo',
}

local classMap = {
    ["WAR"] = "WARRIOR",
    ["CLR"] = "CLERIC",
    ["PAL"] = "PALADIN",
    ["RNG"] = "RANGER",
    ["SHD"] = "SHADOW KNIGHT", ["SK"] = "SHADOW KNIGHT", ["SHADOWKNIGHT"] = "SHADOW KNIGHT",
    ["DRU"] = "DRUID",
    ["MNK"] = "MONK",
    ["BRD"] = "BARD",
    ["ROG"] = "ROGUE",
    ["SHM"] = "SHAMAN",
    ["NEC"] = "NECROMANCER",
    ["WIZ"] = "WIZARD",
    ["MAG"] = "MAGICIAN",
    ["ENC"] = "ENCHANTER",
    ["BST"] = "BEASTLORD", ["BEAST"] = "BEASTLORD", ["BL"] = "BEASTLORD",
    ["BER"] = "BERSERKER",
}

local function normalize_class(name)
    if not name then return nil end
    local up = tostring(name):upper()
    return classMap[up] or up
end

local function extract_class_abbreviation(classString)
    if not classString then return 'UNK' end
    local str = tostring(classString):upper()
    
    -- Check if it's already a 3-letter abbreviation we recognize
    for abbrev, _ in pairs(classMap) do
        if str == abbrev then return abbrev end
    end
    
    -- Extract class from "Race Class" format by looking for class keywords
    local classKeywords = {
        'WARRIOR', 'CLERIC', 'PALADIN', 'RANGER', 'SHADOW KNIGHT', 'SHADOWKNIGHT',
        'DRUID', 'MONK', 'BARD', 'ROGUE', 'SHAMAN', 'NECROMANCER', 'WIZARD',
        'MAGICIAN', 'ENCHANTER', 'BEASTLORD', 'BERSERKER'
    }
    
    for _, class in ipairs(classKeywords) do
        if str:find(class) then
            -- Find the abbreviation for this class
            for abbrev, fullName in pairs(classMap) do
                if fullName == class then
                    return abbrev
                end
            end
        end
    end
    
    return 'UNK'
end

local function can_item_be_used_by_class(itemTLO, className)
    if not itemTLO or not itemTLO() or not className then return false end
    local normalized = normalize_class(className)
    local classCount = tonumber(itemTLO.Classes() or 0) or 0
    if classCount == 0 then return false end
    if classCount >= 16 then return true end
    for i = 1, classCount do
        local ok, itemClass = pcall(function() return itemTLO.Class(i)() end)
        if ok and itemClass then
            local a = normalize_class(itemClass)
            if a == normalized then return true end
        end
    end
    return false
end

local function get_worn_slot_ids(itemTLO)
    local ids = {}
    local count = tonumber(itemTLO.WornSlots() or 0) or 0
    for i = 1, count do
        local ok, sid = pcall(function() return itemTLO.WornSlot(i).ID() end)
        if ok and sid ~= nil then table.insert(ids, tonumber(sid)) end
    end
    return ids
end

local function clear_candidates()
    U._candidates = {}
end

local function add_candidate(c)
    U._candidates[#U._candidates + 1] = c
end

-- Queue a timed inventory refresh for a bot (non-blocking); retries spaced by delaySec
function U.queue_refresh(botName, delaySec, retries)
    if not botName or botName == '' then return end
    U._pending_refresh[botName] = U._pending_refresh[botName] or { nextAt = 0, left = 0, delay = delaySec or 0.8 }
    local entry = U._pending_refresh[botName]
    entry.left = math.max(tonumber(retries or 1) or 1, entry.left)
    entry.delay = tonumber(delaySec or entry.delay or 0.8) or 0.8
    entry.nextAt = os.clock() + entry.delay
end

local function process_pending_refreshes()
    if not bot_inventory or not bot_inventory.requestBotInventory then return end
    local now = os.clock()
    for name, entry in pairs(U._pending_refresh) do
        if entry and (entry.left or 0) > 0 and now >= (entry.nextAt or 0) then
            bot_inventory.requestBotInventory(name)
            entry.left = (entry.left or 1) - 1
            entry.nextAt = now + (entry.delay or 0.8)
            if entry.left <= 0 then U._pending_refresh[name] = nil end
        end
    end
end

local function compute_local_candidates_from_cursor()
    clear_candidates()
    local cur = mq.TLO.Cursor
    if not cur() then
        printf('[EmuBot] No item on cursor for upgrade scan.')
        return 0
    end
    local itemName = cur.Name() or 'Unknown Item'
    local itemID = tonumber(cur.ID() or 0) or 0
    local slotIDs = get_worn_slot_ids(cur)
    if #slotIDs == 0 then
        printf('[EmuBot] Cursor item has no wearable slots.')
        return 0
    end
    local bots = bot_inventory.getAllBots() or {}
    for _, botName in ipairs(bots) do
        local meta = bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[botName]
        local botClass = meta and meta.Class or nil
        local classOK = can_item_be_used_by_class(cur, botClass)
        if classOK then
            for _, sid in ipairs(slotIDs) do
                local slotName = slotNames[sid] or ('Slot ' .. tostring(sid))
                local classAbbrev = extract_class_abbreviation(botClass)
                add_candidate({ bot = botName, class = classAbbrev, slotid = sid, slotname = slotName, itemID = itemID, itemName = itemName })
            end
        end
    end
    return #U._candidates
end

local function ensure_item_on_cursor(itemID)
    if mq.TLO.Cursor() then
        local cid = tonumber(mq.TLO.Cursor.ID() or 0) or 0
        if cid == itemID then return true end
        -- Try to autoinventory to free cursor
        mq.cmd('/autoinventory')
        mq.delay(200)
    end
    -- Find item in inventory
    local fi = mq.TLO.FindItem(itemID)
    if not fi() then return false end
    local packSlot = tonumber(fi.ItemSlot() or 0) or 0
    local subSlot = tonumber(fi.ItemSlot2() or -1) or -1
    if packSlot >= 23 and subSlot >= 0 then
        mq.cmdf('/itemnotify in pack%i %i leftmouseup', (packSlot - 22), (subSlot + 1))
        mq.delay(200)
    else
        -- It may be in main inventory (not inside bag)
        if packSlot >= 23 and subSlot < 0 then
            -- click the top-level slot
            mq.cmdf('/itemnotify in pack%i 1 leftmouseup', (packSlot - 22))
            mq.delay(200)
        end
    end
    return mq.TLO.Cursor() and tonumber(mq.TLO.Cursor.ID() or 0) == itemID
end

local function swap_to_bot(botName, itemID, slotID, slotName, itemName)
    local function printf(fmt, ...) if mq.printf then mq.printf(fmt, ...) else print(string.format(fmt, ...)) end end

    local function ensure_cursor_empty(timeoutMs)
        local deadline = os.clock() + (tonumber(timeoutMs or 1500) or 1500)/1000
        while mq.TLO.Cursor() do
            mq.cmd('/autoinventory')
            mq.delay(100)
            if os.clock() > deadline then return false end
        end
        return true
    end

    local function pick_up_item_by_id_or_name(id, name)
        -- Prefer exact item ID
        local fi = (id and tonumber(id) and tonumber(id) > 0) and mq.TLO.FindItem(tonumber(id)) or nil
        if fi and fi() then
            local packSlot = tonumber(fi.ItemSlot() or 0) or 0
            local subSlot = tonumber(fi.ItemSlot2() or -1) or -1
            if packSlot >= 23 and subSlot >= 0 then
                mq.cmdf('/itemnotify in pack%i %i leftmouseup', (packSlot - 22), (subSlot + 1))
                mq.delay(500)
                return mq.TLO.Cursor() and (tonumber(mq.TLO.Cursor.ID() or 0) == tonumber(id))
            end
        end
        -- Fallback to exact name click
        if name and name ~= '' then
            mq.cmdf('/itemnotify "%s" leftmouseup', name)
            mq.delay(500)
            if id and tonumber(id) and tonumber(id) > 0 then
                return mq.TLO.Cursor() and (tonumber(mq.TLO.Cursor.ID() or 0) == tonumber(id))
            end
            return mq.TLO.Cursor() ~= nil
        end
        return false
    end

    local function perform_swap()
        -- Step 0: make sure cursor is free
        if not ensure_cursor_empty(1200) then
            printf('[EmuBot] Could not clear cursor before swap; aborting.')
            return
        end

        -- Step 1: instruct bot to clear the requested slot (if specified)
        if slotID ~= nil and bot_inventory and bot_inventory.requestBotUnequip then
            bot_inventory.requestBotUnequip(botName, slotID)
            mq.delay(500)
        end

        -- Step 2: pick up the upgrade item from our inventory (by ID or exact name)
        if not pick_up_item_by_id_or_name(itemID, itemName) then
            printf('[EmuBot] Failed to pick up upgrade item "%s" (ID %s).', tostring(itemName or ''), tostring(itemID or ''))
            return
        end

        -- Capture stats/icon/link from the cursor before handing to the bot
        local swapAC, swapHP, swapMana = get_cursor_stats()
        local swapDamage, swapDelay = get_cursor_weapon_stats()
        local swapIcon = 0
        local swapLink, swapRaw = nil, nil
        local cursorTLO = mq.TLO.Cursor
        if cursorTLO and cursorTLO() then
            swapIcon = tonumber(cursorTLO.Icon() or 0) or 0
            if cursorTLO.ItemLink then
                local okClickable, clickable = pcall(function() return cursorTLO.ItemLink('CLICKABLE')() end)
                if okClickable and clickable and clickable ~= '' then swapLink = clickable end
                local okRaw, raw = pcall(function() return cursorTLO.ItemLink('RAW')() end)
                if okRaw and raw and raw ~= '' then swapRaw = raw end
            end
        end

        -- Step 3: give to bot by name
        mq.cmdf('/say ^ig byname %s', botName)
        mq.delay(500)

        -- Step 4: if something still on cursor (server/plugin behaviors), auto-inventory it
        if mq.TLO.Cursor() then
            mq.cmd('/autoinventory')
            mq.delay(500)
        end

        -- Step 5: update cached inventory without forcing ^invlist when possible
        local applied = false
        if bot_inventory and bot_inventory.applySwapFromCursor and slotID ~= nil then
            local ok = bot_inventory.applySwapFromCursor(
                botName,
                slotID,
                slotName,
                itemID,
                itemName,
                swapAC,
                swapHP,
                swapMana,
                swapIcon,
                swapDamage,
                swapDelay,
                swapLink,
                swapRaw
            )
            applied = ok and true or false
        end

        if not applied then
            -- Fallback: request a refresh if direct apply failed
            U.queue_refresh(botName, 0.8, 3)
        end
    end

    if type(_G.enqueueTask) == 'function' then
        _G.enqueueTask(function() perform_swap() end)
    else
        perform_swap()
    end
    return true
end

function U.poll_iu()
    clear_candidates()
    if not mq.TLO.Cursor() then
        printf('[EmuBot] Put the upgrade item on your cursor before polling.')
        return
    end
    printf('[EmuBot] Polling bots with ^iu ...')
    U._show_compare = true
    mq.cmd('/say ^iu')
    -- ^iu responses will be captured by registered events (see U.init()). As a fallback, you may also click Scan Locally.
end

function U.scan_locally()
    local n = compute_local_candidates_from_cursor()
    printf('[EmuBot] Local scan complete. %d candidate upgrade placements found.', n)
end

function U.clear()
    clear_candidates()
end

-- Helper to check if item is a weapon type
local function is_weapon_type(itemType)
    if not itemType then return false end
    local typ = tostring(itemType):upper()
    -- Check for weapon types
    local weaponTypes = {
        '1H SLASHING', '2H SLASHING',
        '1H BLUNT', '2H BLUNT',
        'PIERCING', '2H PIERCING',
        'HAND TO HAND',
        'BOW',
        'THROWING'
    }
    for _, weaponType in ipairs(weaponTypes) do
        if typ:find(weaponType) then
            return true
        end
    end
    return false
end

-- Helper to read cursor item weapon stats safely (without DisplayItem dependency)
get_cursor_weapon_stats = function()
    local cur = mq.TLO.Cursor
    if not cur or not cur() then return 0, 0 end

    -- Check if this is a weapon first
    local isWeapon = is_weapon_type(cur.Type())
    if not isWeapon then
        return 0, 0  -- Not a weapon, return 0 for damage and delay
    end

    -- Get damage and delay directly from cursor item (avoiding DisplayItem dependency)
    local cur_damage = tonumber(cur.Damage() or 0) or 0
    local cur_delay = tonumber(cur.ItemDelay() or 0) or 0

    return cur_damage, cur_delay
end

-- Helper to read cursor item basic stats safely (without DisplayItem dependency)
get_cursor_stats = function()
    local cur = mq.TLO.Cursor
    if not cur or not cur() then return 0, 0, 0 end

    -- Get stats directly from cursor item (avoiding DisplayItem dependency)
    local cur_ac = tonumber(cur.AC() or 0) or 0
    local cur_hp = tonumber(cur.HP() or 0) or 0
    local cur_mana = tonumber(cur.Mana() or 0) or 0

    return cur_ac, cur_hp, cur_mana
end

function U.draw_tab()
    process_pending_refreshes()
    ImGui.Text('Cursor Item:')
    if mq.TLO.Cursor() then
        ImGui.SameLine()
        ImGui.TextColored(0.9, 0.8, 0.2, 1.0, mq.TLO.Cursor.Name() or 'Unknown')
    else
        ImGui.SameLine()
        ImGui.TextColored(0.9, 0.3, 0.3, 1.0, 'None')
    end

    if ImGui.Button('Poll (^iu)##upgrade') then U.poll_iu() end
    ImGui.SameLine()
    if ImGui.Button('Scan Locally##upgrade') then U.scan_locally() end
    ImGui.SameLine()
    if ImGui.Button('Clear##upgrade') then U.clear() end
    ImGui.SameLine()
    if ImGui.Button('Open Compare##upgrade') then U._show_compare = true end

    ImGui.Separator()

    if #U._candidates == 0 then
        ImGui.Text('No upgrade candidates yet. Use Poll (^iu) or Scan Locally.')
        -- Still draw compare window if user opened it (to show empty state)
        if U._show_compare then U.draw_compare_window() end
        return
    end

    -- Check if the cursor item is a weapon to determine the number of columns
    local isWeapon = false
    if mq.TLO.Cursor() then
        isWeapon = is_weapon_type(mq.TLO.Cursor.Type())
    end

    -- Determine number of columns based on whether the item is a weapon (removed Upgrade column)
    local numCols = isWeapon and 9 or 7
    local upgAC, upgHP, upgMana = get_cursor_stats()
    local upgDamage, upgDelay = get_cursor_weapon_stats()

    local displayRows = {}
    for _, row in ipairs(U._candidates or {}) do
        local curItem = nil
        local cAC, cHP, cMana = 0, 0, 0
        local cDamage, cDelay = 0, 0
        if bot_inventory and bot_inventory.getBotEquippedItem and row.bot and row.slotid ~= nil then
            curItem = bot_inventory.getBotEquippedItem(row.bot, row.slotid)
            cAC = tonumber(curItem and curItem.ac or 0) or 0
            cHP = tonumber(curItem and curItem.hp or 0) or 0
            cMana = tonumber(curItem and curItem.mana or 0) or 0

            if isWeapon and curItem and curItem.name then
                local currentItemTLO = mq.TLO.FindItem(string.format('= %s', curItem.name))
                if currentItemTLO and currentItemTLO() then
                    local isCurrentWeapon = is_weapon_type(currentItemTLO.Type())
                    if isCurrentWeapon then
                        cDamage = tonumber(currentItemTLO.Damage() or 0) or 0
                        cDelay = tonumber(currentItemTLO.ItemDelay() or 0) or 0
                    end
                end
            end
        end

        table.insert(displayRows, {
            ref = row,
            slotname = row.slotname or ('Slot ' .. tostring(row.slotid or '?')),
            current = curItem,
            deltaAC = (upgAC or 0) - cAC,
            deltaHP = (upgHP or 0) - cHP,
            deltaMana = (upgMana or 0) - cMana,
            deltaDamage = (upgDamage or 0) - cDamage,
            deltaDelay = (upgDelay or 0) - cDelay,
        })
    end

    if ImGui.BeginTable('EmuBotUpgradeTable', numCols,
            ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.Sortable) then
        ImGui.TableSetupColumn('Bot', ImGuiTableColumnFlags.WidthFixed, 120)
        ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('Slot', ImGuiTableColumnFlags.WidthFixed, 120)
        
        -- Add weapon columns if this is a weapon
        if isWeapon then
            ImGui.TableSetupColumn('Dmg', ImGuiTableColumnFlags.WidthFixed, 60)
            ImGui.TableSetupColumn('Delay', ImGuiTableColumnFlags.WidthFixed, 70)
        end
        
        ImGui.TableSetupColumn('AC', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('HP', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('Mana', ImGuiTableColumnFlags.WidthFixed, 70)
        ImGui.TableSetupColumn('Action', ImGuiTableColumnFlags.WidthFixed, 120)
        ImGui.TableHeadersRow()

        local sortAccessors
        if isWeapon then
            sortAccessors = {
                [1] = function(entry) return entry.ref.bot or '' end,
                [2] = function(entry) return entry.ref.class or '' end,
                [3] = function(entry) return entry.slotname or '' end,
                [4] = function(entry) return entry.deltaDamage or 0 end,
                [5] = function(entry) return entry.deltaDelay or 0 end,
                [6] = function(entry) return entry.deltaAC or 0 end,
                [7] = function(entry) return entry.deltaHP or 0 end,
                [8] = function(entry) return entry.deltaMana or 0 end,
            }
        else
            sortAccessors = {
                [1] = function(entry) return entry.ref.bot or '' end,
                [2] = function(entry) return entry.ref.class or '' end,
                [3] = function(entry) return entry.slotname or '' end,
                [4] = function(entry) return entry.deltaAC or 0 end,
                [5] = function(entry) return entry.deltaHP or 0 end,
                [6] = function(entry) return entry.deltaMana or 0 end,
            }
        end
        applyTableSort(displayRows, ImGui.TableGetSortSpecs(), sortAccessors)

        for i, entry in ipairs(displayRows) do
            local row = entry.ref
            ImGui.TableNextRow()
            ImGui.PushID('upg_' .. tostring(i))

            ImGui.TableNextColumn()
            if ImGui.Selectable((row.bot or 'Unknown') .. '##maintarget_' .. tostring(i), false, ImGuiSelectableFlags.None) then
                -- Target the bot when clicked
                local botName = row.bot
                if botName then
                    local s = mq.TLO.Spawn(string.format('= %s', botName))
                    if s and s.ID and s.ID() and s.ID() > 0 then
                        mq.cmdf('/target id %d', s.ID())
                        printf('[EmuBot] Targeting %s', botName)
                    else
                        mq.cmdf('/target "%s"', botName)
                        printf('[EmuBot] Attempting to target %s', botName)
                    end
                end
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Click to target ' .. (row.bot or 'bot'))
            end

            ImGui.TableNextColumn()
            ImGui.Text(row.class or 'UNK')

            ImGui.TableNextColumn()
            ImGui.Text(entry.slotname)

            -- Weapon deltas (colored) - only if weapon
        if isWeapon then
            -- For weapon Damage: higher is better (green on positive)
            local function color_damage(delta)
                delta = delta or 0
                if delta > 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, '+' .. tostring(delta))
                elseif delta < 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(delta))
                else ImGui.Text('0') end
            end
            -- For weapon Delay: LOWER is better, so invert colors
            local function color_delay(delta)
                delta = delta or 0
                if delta < 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, tostring(delta))
                elseif delta > 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, '+' .. tostring(delta))
                else ImGui.Text('0') end
            end

                ImGui.TableNextColumn(); color_damage(entry.deltaDamage)
                ImGui.TableNextColumn(); color_delay(entry.deltaDelay)
            end

            -- Other deltas (colored)
            local function colortext(delta)
                delta = delta or 0
                if delta > 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, '+' .. tostring(delta))
                elseif delta < 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(delta))
                else ImGui.Text('0') end
            end

            ImGui.TableNextColumn(); colortext(entry.deltaAC)
            ImGui.TableNextColumn(); colortext(entry.deltaHP)
            ImGui.TableNextColumn(); colortext(entry.deltaMana)

            ImGui.TableNextColumn()
            if ImGui.SmallButton('Swap') then
                local ok = swap_to_bot(row.bot, tonumber(row.itemID or 0) or 0, row.slotid, row.slotname, row.itemName)
                if ok then
                    for idx, candidate in ipairs(U._candidates) do
                        if candidate == row then
                            table.remove(U._candidates, idx)
                            break
                        end
                    end
                end
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Note: Bot decides actual equip slot; weapons often equip to Primary if eligible')
            end

            ImGui.PopID()
        end

        ImGui.EndTable()
    end

    if U._show_compare then U.draw_compare_window() end
end

local function slot_from_phrase(phrase)
    if not phrase then return nil end
    local p = tostring(phrase):lower()
    local map = {
        ['head']=2, ['face']=3, ['neck']=5, ['shoulders']=6, ['arms']=7, ['back']=8,
        ['range']=11, ['hands']=12, ['primary']=13, ['secondary']=14, ['chest']=17,
        ['legs']=18, ['feet']=19, ['waist']=20, ['power source']=21, ['ammo']=22, ['charm']=0,
    }
    -- Fingers/Ears/Wrists with index
    local function with_index(base, one, two)
        if p:find(base) then
            local id = nil
            if p:find('1') then id = one elseif p:find('2') then id = two end
            return id
        end
        return nil
    end
    local id = with_index('finger', 15, 16) or with_index('ear', 1, 4) or with_index('wrist', 9, 10) or map[p]
    if not id then return nil end
    return id, slotNames[id] or phrase
end

local function on_iu_basic(line, name, slotPhrase)
    local itemID = tonumber(mq.TLO.Cursor.ID() or 0) or 0
    local itemName = mq.TLO.Cursor.Name() or 'Item'
    local sid, sname = slot_from_phrase(slotPhrase)
    if not sid then return end
    
    -- Get bot class from metadata if available
    local botClass = 'UNK'
    if bot_inventory and bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[name] then
        botClass = bot_inventory.bot_list_capture_set[name].Class or 'UNK'
    end
    local classAbbrev = extract_class_abbreviation(botClass)
    
    add_candidate({ bot = name, class = classAbbrev, slotid = sid, slotname = sname, itemID = itemID, itemName = itemName })
    U._show_compare = true
end

local function on_iu_instead(line, name, slotPhrase, currentItem)
    -- We currently resolve current item via bot_inventory; still capture name/slot
    on_iu_basic(line, name, slotPhrase)
end

function U.init()
    if U._events_inited then return end
    -- Examples from screenshot:
    -- Cadwen says, 'I can use that for my Finger 1! Would you like to give it to me?'
    -- Dragkan says, 'I can use that for my Finger 1 instead of my Elegant Adept's Ring! Would you like to remove my item?'
    -- Fixed: Made patterns mutually exclusive to prevent duplicate slot capture
    mq.event('EmuBot_IU_Give', "#1# says, 'I can use that for my #2#! Would you like to give it to me?'", on_iu_basic)
    mq.event('EmuBot_IU_Replace', "#1# says, 'I can use that for my #2# instead of my #3#! #*", on_iu_instead)
    U._events_inited = true
end

-- Draw a comparison window showing current equipped vs upgrade stats (AC/HP/Mana), with quick swap per row
function U.draw_compare_window()
    if not U._show_compare then return end
    process_pending_refreshes()
    local wndFlags = ImGuiWindowFlags.None
    local isOpen, visible = ImGui.Begin('Upgrade Comparison##EmuBot', true, wndFlags)
    if not isOpen then
        U._show_compare = false
        ImGui.End()
        return
    end

    -- Gather upgrade stats from cursor (prefer DisplayItem base stats via get_cursor_stats)
    local cur = mq.TLO.Cursor
    local upgName = cur() and (cur.Name() or 'Upgrade Item') or 'Upgrade Item'
    local upgAC, upgHP, upgMana = get_cursor_stats()
    local upgDamage, upgDelay = get_cursor_weapon_stats()
    
    -- Check if the cursor item is a weapon to determine if we should show weapon stats
    local isWeapon = false
    if cur and cur() then
        isWeapon = is_weapon_type(cur.Type())
    end

    -- Highlight the upgrade item header in a gold-ish color for visibility
    local goldR, goldG, goldB = 0.95, 0.85, 0.20
    ImGui.TextColored(goldR, goldG, goldB, 1.0, 'Upgrade Item: ' .. tostring(upgName))
    ImGui.SameLine()
    if isWeapon then
        ImGui.TextColored(goldR, goldG, goldB, 1.0, string.format('(AC %d  HP %d  Mana %d  Dmg %d  Delay %d)', upgAC, upgHP, upgMana, upgDamage, upgDelay))
    else
        ImGui.TextColored(goldR, goldG, goldB, 1.0, string.format('(AC %d  HP %d  Mana %d)', upgAC, upgHP, upgMana))
    end
    ImGui.Separator()

    if #U._candidates == 0 then
        ImGui.Text('No candidates to compare.')
        ImGui.End()
        return
    end

    -- Determine number of columns based on whether the item is a weapon (removed Upgrade column)
    local numCols = isWeapon and 10 or 8
    local compareRows = {}
    for _, row in ipairs(U._candidates or {}) do
        local curItem = nil
        if bot_inventory and bot_inventory.getBotEquippedItem and row.bot and row.slotid ~= nil then
            curItem = bot_inventory.getBotEquippedItem(row.bot, row.slotid)
        end
        local cAC = tonumber(curItem and curItem.ac or 0) or 0
        local cHP = tonumber(curItem and curItem.hp or 0) or 0
        local cMana = tonumber(curItem and curItem.mana or 0) or 0
        local cDamage = tonumber(curItem and curItem.damage or 0) or 0
        local cDelay = tonumber(curItem and curItem.delay or 0) or 0
        if isWeapon and curItem and curItem.name and (cDamage == 0 and cDelay == 0) then
            local currentItemTLO = mq.TLO.FindItem(string.format('= %s', curItem.name or ''))
            if currentItemTLO and currentItemTLO() then
                cDamage = tonumber(currentItemTLO.Damage() or 0) or 0
                cDelay = tonumber(currentItemTLO.ItemDelay() or 0) or 0
            end
        end
        table.insert(compareRows, {
            ref = row,
            stats = {
                item = curItem,
                ac = cAC,
                hp = cHP,
                mana = cMana,
                damage = cDamage,
                delay = cDelay,
            },
        })
    end

    local closeAfterSwap = false
    if ImGui.BeginTable('EmuBotUpgradeCompare', numCols,
            ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.Sortable) then
        applyTableSort(compareRows, ImGui.TableGetSortSpecs(), {
            [1] = function(entry) return entry.ref.bot or '' end,
            [2] = function(entry) return entry.ref.class or '' end,
            [3] = function(entry) return entry.ref.slotname or ('Slot ' .. tostring(entry.ref.slotid or '?')) end,
            [4] = function(entry)
                return entry.stats.item and entry.stats.item.name or ''
            end,
            [5] = isWeapon and function(entry)
                return (upgDamage or 0) - (entry.stats.damage or 0)
            end or nil,
            [6] = isWeapon and function(entry)
                return (upgDelay or 0) - (entry.stats.delay or 0)
            end or nil,
            [isWeapon and 7 or 5] = function(entry)
                return (upgAC or 0) - (entry.stats.ac or 0)
            end,
            [isWeapon and 8 or 6] = function(entry)
                return (upgHP or 0) - (entry.stats.hp or 0)
            end,
            [isWeapon and 9 or 7] = function(entry)
                return (upgMana or 0) - (entry.stats.mana or 0)
            end,
        })
        ImGui.TableSetupColumn('Bot', ImGuiTableColumnFlags.WidthFixed, 120)
        ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('Slot', ImGuiTableColumnFlags.WidthFixed, 120)
        ImGui.TableSetupColumn('Current', ImGuiTableColumnFlags.WidthStretch)
        
        -- Add weapon columns if this is a weapon
        if isWeapon then
            ImGui.TableSetupColumn('Dmg', ImGuiTableColumnFlags.WidthFixed, 60)
            ImGui.TableSetupColumn('Delay', ImGuiTableColumnFlags.WidthFixed, 70)
        end
        
        ImGui.TableSetupColumn('AC', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('HP', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('Mana', ImGuiTableColumnFlags.WidthFixed, 70)
        ImGui.TableSetupColumn('Action', ImGuiTableColumnFlags.WidthFixed, 90)
        ImGui.TableHeadersRow()

        for i, entry in ipairs(compareRows) do
            local row = entry.ref
            local stats = entry.stats
            ImGui.TableNextRow()
            ImGui.PushID('cmp_' .. tostring(i))

            local curItem = stats.item
            local dAC = (upgAC or 0) - (stats.ac or 0)
            local dHP = (upgHP or 0) - (stats.hp or 0)
            local dMana = (upgMana or 0) - (stats.mana or 0)
            local dDamage = (upgDamage or 0) - (stats.damage or 0)
            local dDelay = (upgDelay or 0) - (stats.delay or 0)

            ImGui.TableNextColumn()
            if ImGui.Selectable((row.bot or 'Unknown') .. '##target_' .. tostring(i), false, ImGuiSelectableFlags.None) then
                -- Target the bot when clicked
                local botName = row.bot
                if botName then
                    local s = mq.TLO.Spawn(string.format('= %s', botName))
                    if s and s.ID and s.ID() and s.ID() > 0 then
                        mq.cmdf('/target id %d', s.ID())
                        printf('[EmuBot] Targeting %s', botName)
                    else
                        mq.cmdf('/target "%s"', botName)
                        printf('[EmuBot] Attempting to target %s', botName)
                    end
                end
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Click to target ' .. (row.bot or 'bot'))
            end
            ImGui.TableNextColumn(); ImGui.Text(row.class or 'UNK')
            ImGui.TableNextColumn(); ImGui.Text(row.slotname or ('Slot ' .. tostring(row.slotid or '?')))

            -- Current (name with clickable link)
            ImGui.TableNextColumn()
            if curItem and curItem.name and curItem.name ~= '' then
                -- Create a link to the current item if we have itemlink data
                if curItem.itemlink and curItem.itemlink ~= '' then
                    local links = mq.ExtractLinks(curItem.itemlink)
                    if links and #links > 0 then
                        if ImGui.Selectable(curItem.name, false, ImGuiSelectableFlags.None) then
                            -- Execute the item link to display it
                            if mq.ExecuteTextLink then
                                mq.ExecuteTextLink(links[1])
                            end
                        end
                        if ImGui.IsItemHovered() then ImGui.SetTooltip('Click to inspect current item') end
                    else
                        -- Fallback to regular text if no link data available
                        ImGui.Text(curItem.name)
                    end
                else
                    -- If no itemlink data, just show as text for now
                    ImGui.Text(curItem.name)
                end
            else
                ImGui.Text('--')
            end

            -- Weapon Deltas (colored) - only if weapon
            if isWeapon then
                -- For weapon Damage: higher is better (green on positive)
                local function color_damage(delta)
                    if delta > 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, '+' .. tostring(delta))
                    elseif delta < 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(delta))
                    else ImGui.Text('0') end
                end
                -- For weapon Delay: LOWER is better, so invert colors
                local function color_delay(delta)
                    if delta < 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, tostring(delta))
                    elseif delta > 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, '+' .. tostring(delta))
                    else ImGui.Text('0') end
                end

                ImGui.TableNextColumn(); color_damage(dDamage)
                ImGui.TableNextColumn(); color_delay(dDelay)
            end

            -- Other Deltas (colored)
            local function colortext(delta)
                if delta > 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, '+' .. tostring(delta))
                elseif delta < 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(delta))
                else ImGui.Text('0') end
            end

            ImGui.TableNextColumn(); colortext(dAC)
            ImGui.TableNextColumn(); colortext(dHP)
            ImGui.TableNextColumn(); colortext(dMana)

            -- Action (inline)
            ImGui.TableNextColumn()
            local swapped = false
            if ImGui.SmallButton('Swap##cmp' .. tostring(i)) then
                if swap_to_bot(row.bot, tonumber(row.itemID or 0) or 0, row.slotid, row.slotname, row.itemName) then
                    table.remove(U._candidates, i)
                    swapped = true
                    closeAfterSwap = true
                end
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Note: Bot decides actual equip slot; weapons often equip to Primary if eligible')
            end
            
            ImGui.PopID()
            if swapped then break end
        end

        ImGui.EndTable()
    end

    if closeAfterSwap and U._close_window_on_swap then
        U._show_compare = false
        ImGui.End()
        return
    end

    ImGui.End()
end

return U
