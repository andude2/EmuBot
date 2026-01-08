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
U._last_cursor_id = nil
U._level_too_low = false
U._show_advanced_stats = false

function U.set_close_window_on_swap(value)
    U._close_window_on_swap = value and true or false
end

function U.get_close_window_on_swap()
    return U._close_window_on_swap
end

-- Forward declaration so functions defined earlier can call it safely
local get_cursor_stats
local get_cursor_weapon_stats
local get_cursor_all_stats
local get_item_all_stats
local get_cached_item_all_stats

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

local function get_main_char_name()
    local me = mq.TLO.Me
    if not me then return nil end
    local okClean, clean = pcall(function() return me.CleanName() end)
    if okClean and clean and clean ~= '' then return tostring(clean) end
    local okName, name = pcall(function() return me.Name() end)
    if okName and name and name ~= '' then return tostring(name) end
    return nil
end

local function is_main_char_name(name)
    if not name or name == '' then return false end
    local myName = get_main_char_name()
    if not myName or myName == '' then return false end
    return tostring(name):lower() == tostring(myName):lower()
end

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
    U._level_too_low = false
end

local function add_candidate(c)
    if not c then return end
    if not c.isMainChar and is_main_char_name(c.bot) then
        return
    end
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

-- Helper function to add main character to candidates list
local function add_main_char_candidates()
    local cur = mq.TLO.Cursor
    if not cur() then return 0 end

    local itemName = cur.Name() or 'Unknown Item'
    local itemID = tonumber(cur.ID() or 0) or 0
    local slotIDs = get_worn_slot_ids(cur)
    if #slotIDs == 0 then return 0 end

    -- Check level requirement
    local requiredLevel = tonumber(cur.RequiredLevel() or 0) or 0
    local myLevel = tonumber(mq.TLO.Me.Level() or 0) or 0
    if requiredLevel > myLevel then
        U._level_too_low = true
        return 0  -- Item level too high for main character
    end

    local myName = get_main_char_name() or 'Me'
    local myClass = mq.TLO.Me.Class.ShortName() or 'UNK'
    local classOK = can_item_be_used_by_class(cur, myClass)
    local count = 0
    if classOK then
        for _, sid in ipairs(slotIDs) do
            local slotName = slotNames[sid] or ('Slot ' .. tostring(sid))
            local classAbbrev = extract_class_abbreviation(myClass)
            add_candidate({ bot = myName, class = classAbbrev, slotid = sid, slotname = slotName, itemID = itemID, itemName = itemName, isMainChar = true })
            count = count + 1
        end
    end
    return count
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

    -- Check level requirement once for the cursor item
    local requiredLevel = tonumber(cur.RequiredLevel() or 0) or 0

    -- Add the main character (yourself) to the comparison
    add_main_char_candidates()

    -- Add bots to the comparison
    local bots = bot_inventory.getAllBots() or {}
    for _, botName in ipairs(bots) do
        local meta = bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[botName]
        local botClass = meta and meta.Class or nil
        local botLevel = meta and tonumber(meta.Level or 0) or 0

        -- Check level requirement for bot
        if requiredLevel > botLevel and botLevel > 0 then
            -- Skip this bot, level too low
            U._level_too_low = true
        else
            local classOK = can_item_be_used_by_class(cur, botClass)
            if classOK then
                for _, sid in ipairs(slotIDs) do
                    local slotName = slotNames[sid] or ('Slot ' .. tostring(sid))
                    local classAbbrev = extract_class_abbreviation(botClass)
                    add_candidate({ bot = botName, class = classAbbrev, slotid = sid, slotname = slotName, itemID = itemID, itemName = itemName, isMainChar = false })
                end
            end
        end
    end
    return #U._candidates
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
        local swapAllStats = get_cursor_all_stats()  -- Get all advanced stats
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
                swapRaw,
                swapAllStats  -- Pass all advanced stats
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

local function get_exchange_slot_name(displaySlotName)
    -- Map display slot names to /exchange command slot names
    local slotMap = {
        ['Charm'] = 'charm',
        ['Left Ear'] = 'leftear',
        ['Head'] = 'head',
        ['Face'] = 'face',
        ['Right Ear'] = 'rightear',
        ['Neck'] = 'neck',
        ['Shoulders'] = 'shoulder',
        ['Arms'] = 'arms',
        ['Back'] = 'back',
        ['Left Wrist'] = 'leftwrist',
        ['Right Wrist'] = 'rightwrist',
        ['Range'] = 'ranged',
        ['Hands'] = 'hand',
        ['Primary'] = 'mainhand',
        ['Secondary'] = 'offhand',
        ['Left Ring'] = 'leftfinger',
        ['Right Ring'] = 'rightfinger',
        ['Chest'] = 'chest',
        ['Legs'] = 'leg',
        ['Feet'] = 'feet',
        ['Waist'] = 'waist',
        ['Power Source'] = 'powersource',
        ['Ammo'] = 'ammo',
    }
    return slotMap[displaySlotName] or displaySlotName
end

local function get_slot_id(displaySlotName)
    -- Map display slot names to numeric slot IDs for manual swapping
    local slotMap = {
        ['Charm'] = 0,
        ['Left Ear'] = 1,
        ['Head'] = 2,
        ['Face'] = 3,
        ['Right Ear'] = 4,
        ['Neck'] = 5,
        ['Shoulders'] = 6,
        ['Arms'] = 7,
        ['Back'] = 8,
        ['Left Wrist'] = 9,
        ['Right Wrist'] = 10,
        ['Range'] = 11,
        ['Hands'] = 12,
        ['Primary'] = 13,
        ['Secondary'] = 14,
        ['Left Ring'] = 15,
        ['Right Ring'] = 16,
        ['Chest'] = 17,
        ['Legs'] = 18,
        ['Feet'] = 19,
        ['Waist'] = 20,
        ['Power Source'] = 21,
        ['Ammo'] = 22,
    }
    return slotMap[displaySlotName]
end

local function is_exchange_plugin_loaded()
    if not mq.TLO.Plugin then return false end
    local plugin = mq.TLO.Plugin('MQ2Exchange')
    if not plugin then return false end
    return plugin.IsLoaded() or false
end

local function swap_to_main_char(itemID, slotID, slotName, itemName)
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

    local function perform_manual_swap()
        -- Manual swap process when MQ2Exchange isn't loaded
        printf('[EmuBot] MQ2Exchange not loaded, using manual swap method...')

        -- Step 1: Get the equipment slot ID
        local equipSlotID = get_slot_id(slotName)
        if not equipSlotID then
            printf('[EmuBot] Unknown equipment slot: %s', tostring(slotName or ''))
            -- Try to clear cursor
            if mq.TLO.Cursor() then
                mq.cmd('/autoinventory')
                mq.delay(300)
            end
            return
        end

        -- Step 2: Click the equipment slot to swap items (new item goes to slot, old item goes to cursor)
        mq.cmdf('/itemnotify %d leftmouseup', equipSlotID)
        mq.delay(500)

        -- Step 4: Autoinventory the old item that's now on cursor
        if mq.TLO.Cursor() then
            mq.cmd('/autoinventory')
            mq.delay(500)
        end

        if ensure_cursor_empty(500) then
            printf('[EmuBot] Successfully swapped "%s" to your %s slot.', tostring(itemName or ''), tostring(slotName or ''))
        else
            printf('[EmuBot] Warning: Swap completed but cursor still has an item.')
        end
    end

    local function perform_swap_with_exchange()
        -- Swap using MQ2Exchange plugin
        -- Step 2: autoinventory the item
        mq.cmd('/autoinventory')
        mq.delay(500)

        -- Step 3: exchange the item to the slot
        if itemName and itemName ~= '' and slotName and slotName ~= '' then
            local exchangeSlot = get_exchange_slot_name(slotName)
            mq.cmdf('/exchange "%s" %s', itemName, exchangeSlot)
            mq.delay(500)
            printf('[EmuBot] Swapped "%s" to your %s slot.', tostring(itemName or ''), tostring(slotName or ''))
        else
            printf('[EmuBot] Failed to swap: missing item name or slot name.')
        end
    end

    local function perform_swap()
        -- Check if MQ2Exchange is loaded and use appropriate swap method
        if is_exchange_plugin_loaded() then
            perform_swap_with_exchange()
        else
            perform_manual_swap()
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
    -- Add main character to comparison first
    add_main_char_candidates()
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

function U.poll_cursor_changes()
    local cursor = mq.TLO.Cursor
    local currentId = nil
    if cursor and cursor() then
        local ok, cid = pcall(function() return cursor.ID() end)
        if ok then currentId = tonumber(cid or 0) or 0 end
    end

    if currentId == U._last_cursor_id then return end
    U._last_cursor_id = currentId

    if currentId and currentId > 0 then
        U.clear()
        U.poll_iu()
    else
        U.clear()
        U._show_compare = false
    end
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

-- Helper to read all item stats from cursor (for advanced stats view)
get_cursor_all_stats = function()
    local cur = mq.TLO.Cursor
    if not cur or not cur() then return {} end

    local stats = {}
    -- Basic stats
    stats.ac = tonumber(cur.AC() or 0) or 0
    stats.hp = tonumber(cur.HP() or 0) or 0
    stats.mana = tonumber(cur.Mana() or 0) or 0
    stats.endurance = tonumber(cur.Endurance() or 0) or 0

    -- Weapon stats
    stats.damage = tonumber(cur.Damage() or 0) or 0
    stats.delay = tonumber(cur.ItemDelay() or 0) or 0

    -- Core attributes
    stats.str = tonumber(cur.STR() or 0) or 0
    stats.dex = tonumber(cur.DEX() or 0) or 0
    stats.agi = tonumber(cur.AGI() or 0) or 0
    stats.sta = tonumber(cur.STA() or 0) or 0
    stats.int = tonumber(cur.INT() or 0) or 0
    stats.wis = tonumber(cur.WIS() or 0) or 0
    stats.cha = tonumber(cur.CHA() or 0) or 0

    -- Heroic stats
    stats.heroicStr = tonumber(cur.HeroicSTR() or 0) or 0
    stats.heroicDex = tonumber(cur.HeroicDEX() or 0) or 0
    stats.heroicAgi = tonumber(cur.HeroicAGI() or 0) or 0
    stats.heroicSta = tonumber(cur.HeroicSTA() or 0) or 0
    stats.heroicInt = tonumber(cur.HeroicINT() or 0) or 0
    stats.heroicWis = tonumber(cur.HeroicWIS() or 0) or 0
    stats.heroicCha = tonumber(cur.HeroicCHA() or 0) or 0

    -- Resistances
    stats.svMagic = tonumber((cur.SVMagic and cur.SVMagic()) or 0) or 0
    stats.svFire = tonumber((cur.SVFire and cur.SVFire()) or 0) or 0
    stats.svCold = tonumber((cur.SVCold and cur.SVCold()) or 0) or 0
    stats.svPoison = tonumber((cur.SVPoison and cur.SVPoison()) or 0) or 0
    stats.svDisease = tonumber((cur.SVDisease and cur.SVDisease()) or 0) or 0
    stats.svCorruption = tonumber((cur.SVCorruption and cur.SVCorruption()) or 0) or 0

    -- Combat stats
    stats.attack = tonumber(cur.Attack() or 0) or 0
    stats.haste = tonumber(cur.Haste() or 0) or 0

    return stats
end

-- Helper to read all item stats from an itemTLO (for advanced stats view)
get_item_all_stats = function(itemTLO)
    if not itemTLO or not itemTLO() then return {} end

    local stats = {}
    -- Basic stats
    stats.ac = tonumber(itemTLO.AC() or 0) or 0
    stats.hp = tonumber(itemTLO.HP() or 0) or 0
    stats.mana = tonumber(itemTLO.Mana() or 0) or 0
    stats.endurance = tonumber(itemTLO.Endurance() or 0) or 0

    -- Weapon stats
    stats.damage = tonumber(itemTLO.Damage() or 0) or 0
    stats.delay = tonumber(itemTLO.ItemDelay() or 0) or 0

    -- Core attributes
    stats.str = tonumber(itemTLO.STR() or 0) or 0
    stats.dex = tonumber(itemTLO.DEX() or 0) or 0
    stats.agi = tonumber(itemTLO.AGI() or 0) or 0
    stats.sta = tonumber(itemTLO.STA() or 0) or 0
    stats.int = tonumber(itemTLO.INT() or 0) or 0
    stats.wis = tonumber(itemTLO.WIS() or 0) or 0
    stats.cha = tonumber(itemTLO.CHA() or 0) or 0

    -- Heroic stats
    stats.heroicStr = tonumber(itemTLO.HeroicSTR() or 0) or 0
    stats.heroicDex = tonumber(itemTLO.HeroicDEX() or 0) or 0
    stats.heroicAgi = tonumber(itemTLO.HeroicAGI() or 0) or 0
    stats.heroicSta = tonumber(itemTLO.HeroicSTA() or 0) or 0
    stats.heroicInt = tonumber(itemTLO.HeroicINT() or 0) or 0
    stats.heroicWis = tonumber(itemTLO.HeroicWIS() or 0) or 0
    stats.heroicCha = tonumber(itemTLO.HeroicCHA() or 0) or 0

    -- Resistances
    stats.svMagic = tonumber((itemTLO.SVMagic and itemTLO.SVMagic()) or 0) or 0
    stats.svFire = tonumber((itemTLO.SVFire and itemTLO.SVFire()) or 0) or 0
    stats.svCold = tonumber((itemTLO.SVCold and itemTLO.SVCold()) or 0) or 0
    stats.svPoison = tonumber((itemTLO.SVPoison and itemTLO.SVPoison()) or 0) or 0
    stats.svDisease = tonumber((itemTLO.SVDisease and itemTLO.SVDisease()) or 0) or 0
    stats.svCorruption = tonumber((itemTLO.SVCorruption and itemTLO.SVCorruption()) or 0) or 0

    -- Combat stats
    stats.attack = tonumber(itemTLO.Attack() or 0) or 0
    stats.haste = tonumber(itemTLO.Haste() or 0) or 0

    return stats
end

local function get_cached_value(item, key)
    if not item then return 0 end
    return tonumber(item[key] or 0) or 0
end

get_cached_item_all_stats = function(item)
    if not item then return {} end
    local stats = {}
    stats.str = get_cached_value(item, 'str')
    stats.dex = get_cached_value(item, 'dex')
    stats.agi = get_cached_value(item, 'agi')
    stats.sta = get_cached_value(item, 'sta')
    stats.int = get_cached_value(item, 'int')
    stats.wis = get_cached_value(item, 'wis')
    stats.cha = get_cached_value(item, 'cha')

    stats.heroicStr = get_cached_value(item, 'heroicStr')
    stats.heroicDex = get_cached_value(item, 'heroicDex')
    stats.heroicAgi = get_cached_value(item, 'heroicAgi')
    stats.heroicSta = get_cached_value(item, 'heroicSta')
    stats.heroicInt = get_cached_value(item, 'heroicInt')
    stats.heroicWis = get_cached_value(item, 'heroicWis')
    stats.heroicCha = get_cached_value(item, 'heroicCha')

    stats.svMagic = get_cached_value(item, 'svMagic')
    stats.svFire = get_cached_value(item, 'svFire')
    stats.svCold = get_cached_value(item, 'svCold')
    stats.svPoison = get_cached_value(item, 'svPoison')
    stats.svDisease = get_cached_value(item, 'svDisease')
    stats.svCorruption = get_cached_value(item, 'svCorruption')

    return stats
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
    ImGui.SameLine()
    U._show_advanced_stats = ImGui.Checkbox('Advanced Stats##upgrade', U._show_advanced_stats)

    ImGui.Separator()

    if #U._candidates == 0 then
        if U._level_too_low then
            ImGui.TextColored(0.9, 0.5, 0.2, 1.0, 'Item Required Level Exceeds Current Level')
        else
            ImGui.Text('No upgrade candidates yet. Use Poll (^iu) or Scan Locally.')
        end
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

    -- Add additional columns if advanced stats are enabled
    if U._show_advanced_stats then
        numCols = numCols + 20  -- +7 core stats, +7 heroic stats, +6 resists
    end

    local upgAC, upgHP, upgMana = get_cursor_stats()
    local upgDamage, upgDelay = get_cursor_weapon_stats()
    local upgAllStats = U._show_advanced_stats and get_cursor_all_stats() or {}

    -- Helper function to build display row data
    local function build_display_row(row)
        local curItem = nil
        local cAC, cHP, cMana = 0, 0, 0
        local cDamage, cDelay = 0, 0
        local curAllStats = {}

        -- Check if this is the main character
        if row.isMainChar then
            -- Get equipped item stats from main character
            local equippedItem = mq.TLO.Me.Inventory(row.slotid)
            if equippedItem and equippedItem() then
                cAC = tonumber(equippedItem.AC() or 0) or 0
                cHP = tonumber(equippedItem.HP() or 0) or 0
                cMana = tonumber(equippedItem.Mana() or 0) or 0

                if isWeapon then
                    local isCurrentWeapon = is_weapon_type(equippedItem.Type())
                    if isCurrentWeapon then
                        cDamage = tonumber(equippedItem.Damage() or 0) or 0
                        cDelay = tonumber(equippedItem.ItemDelay() or 0) or 0
                    end
                end

                -- Get all stats if advanced mode is enabled
                if U._show_advanced_stats then
                    curAllStats = get_item_all_stats(equippedItem)
                end

                -- Create a minimal curItem structure for display consistency
                curItem = {
                    name = equippedItem.Name() or '',
                    ac = cAC,
                    hp = cHP,
                    mana = cMana
                }
            end
        elseif bot_inventory and bot_inventory.getBotEquippedItem and row.bot and row.slotid ~= nil then
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

                    -- Get all stats if advanced mode is enabled
                    if U._show_advanced_stats then
                        curAllStats = get_item_all_stats(currentItemTLO)
                    end
                end
            end
        end

        if U._show_advanced_stats and next(curAllStats) == nil and curItem then
            curAllStats = get_cached_item_all_stats(curItem)
        end

        local displayRow = {
            ref = row,
            slotname = row.slotname or ('Slot ' .. tostring(row.slotid or '?')),
            current = curItem,
            deltaAC = (upgAC or 0) - cAC,
            deltaHP = (upgHP or 0) - cHP,
            deltaMana = (upgMana or 0) - cMana,
            deltaDamage = (upgDamage or 0) - cDamage,
            deltaDelay = (upgDelay or 0) - cDelay,
        }

        -- Add advanced stat deltas if enabled
        if U._show_advanced_stats then
            displayRow.deltaSTR = (upgAllStats.str or 0) - (curAllStats.str or 0)
            displayRow.deltaDEX = (upgAllStats.dex or 0) - (curAllStats.dex or 0)
            displayRow.deltaAGI = (upgAllStats.agi or 0) - (curAllStats.agi or 0)
            displayRow.deltaSTA = (upgAllStats.sta or 0) - (curAllStats.sta or 0)
            displayRow.deltaINT = (upgAllStats.int or 0) - (curAllStats.int or 0)
            displayRow.deltaWIS = (upgAllStats.wis or 0) - (curAllStats.wis or 0)
            displayRow.deltaCHA = (upgAllStats.cha or 0) - (curAllStats.cha or 0)

            displayRow.deltaHSTR = (upgAllStats.heroicStr or 0) - (curAllStats.heroicStr or 0)
            displayRow.deltaHDEX = (upgAllStats.heroicDex or 0) - (curAllStats.heroicDex or 0)
            displayRow.deltaHAGI = (upgAllStats.heroicAgi or 0) - (curAllStats.heroicAgi or 0)
            displayRow.deltaHSTA = (upgAllStats.heroicSta or 0) - (curAllStats.heroicSta or 0)
            displayRow.deltaHINT = (upgAllStats.heroicInt or 0) - (curAllStats.heroicInt or 0)
            displayRow.deltaHWIS = (upgAllStats.heroicWis or 0) - (curAllStats.heroicWis or 0)
            displayRow.deltaHCHA = (upgAllStats.heroicCha or 0) - (curAllStats.heroicCha or 0)

            displayRow.deltaSvMagic = (upgAllStats.svMagic or 0) - (curAllStats.svMagic or 0)
            displayRow.deltaSvFire = (upgAllStats.svFire or 0) - (curAllStats.svFire or 0)
            displayRow.deltaSvCold = (upgAllStats.svCold or 0) - (curAllStats.svCold or 0)
            displayRow.deltaSvPoison = (upgAllStats.svPoison or 0) - (curAllStats.svPoison or 0)
            displayRow.deltaSvDisease = (upgAllStats.svDisease or 0) - (curAllStats.svDisease or 0)
            displayRow.deltaSvCorruption = (upgAllStats.svCorruption or 0) - (curAllStats.svCorruption or 0)
        end

        return displayRow
    end

    -- Helper function to render table rows
    local function render_table_rows(rows, startIndex)
        -- Define color functions inside to avoid redefinition
        local function color_damage(delta)
            delta = delta or 0
            if delta > 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, '+' .. tostring(delta))
            elseif delta < 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(delta))
            else ImGui.Text('0') end
        end
        local function color_delay(delta)
            delta = delta or 0
            if delta < 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, tostring(delta))
            elseif delta > 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, '+' .. tostring(delta))
            else ImGui.Text('0') end
        end
        local function colortext(delta)
            delta = delta or 0
            if delta > 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, '+' .. tostring(delta))
            elseif delta < 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(delta))
            else ImGui.Text('0') end
        end

        for i, entry in ipairs(rows) do
            local row = entry.ref
            ImGui.TableNextRow()
            ImGui.PushID('upg_' .. tostring(startIndex + i))

            ImGui.TableNextColumn()
            if ImGui.Selectable((row.bot or 'Unknown') .. '##maintarget_' .. tostring(startIndex + i), false, ImGuiSelectableFlags.None) then
                -- Target the bot when clicked (skip for main char)
                if not row.isMainChar then
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
            end
            if ImGui.IsItemHovered() then
                if row.isMainChar then
                    ImGui.SetTooltip('This is you')
                else
                    ImGui.SetTooltip('Click to target ' .. (row.bot or 'bot'))
                end
            end

            ImGui.TableNextColumn()
            ImGui.Text(row.class or 'UNK')

            ImGui.TableNextColumn()
            ImGui.Text(entry.slotname)

            -- Weapon deltas (colored) - only if weapon
            if isWeapon then
                ImGui.TableNextColumn(); color_damage(entry.deltaDamage)
                ImGui.TableNextColumn(); color_delay(entry.deltaDelay)
            end

            -- Other deltas (colored)
            ImGui.TableNextColumn(); colortext(entry.deltaAC)
            ImGui.TableNextColumn(); colortext(entry.deltaHP)
            ImGui.TableNextColumn(); colortext(entry.deltaMana)

            -- Advanced stat deltas (if enabled)
            if U._show_advanced_stats then
                -- Core stats
                ImGui.TableNextColumn(); colortext(entry.deltaSTR)
                ImGui.TableNextColumn(); colortext(entry.deltaDEX)
                ImGui.TableNextColumn(); colortext(entry.deltaAGI)
                ImGui.TableNextColumn(); colortext(entry.deltaSTA)
                ImGui.TableNextColumn(); colortext(entry.deltaINT)
                ImGui.TableNextColumn(); colortext(entry.deltaWIS)
                ImGui.TableNextColumn(); colortext(entry.deltaCHA)

                -- Heroic stats
                ImGui.TableNextColumn(); colortext(entry.deltaHSTR)
                ImGui.TableNextColumn(); colortext(entry.deltaHDEX)
                ImGui.TableNextColumn(); colortext(entry.deltaHAGI)
                ImGui.TableNextColumn(); colortext(entry.deltaHSTA)
                ImGui.TableNextColumn(); colortext(entry.deltaHINT)
                ImGui.TableNextColumn(); colortext(entry.deltaHWIS)
                ImGui.TableNextColumn(); colortext(entry.deltaHCHA)

                -- Resists
                ImGui.TableNextColumn(); colortext(entry.deltaSvMagic)
                ImGui.TableNextColumn(); colortext(entry.deltaSvFire)
                ImGui.TableNextColumn(); colortext(entry.deltaSvCold)
                ImGui.TableNextColumn(); colortext(entry.deltaSvPoison)
                ImGui.TableNextColumn(); colortext(entry.deltaSvDisease)
                ImGui.TableNextColumn(); colortext(entry.deltaSvCorruption)
            end

            ImGui.TableNextColumn()
            if ImGui.SmallButton('Swap') then
                local ok
                if row.isMainChar then
                    ok = swap_to_main_char(tonumber(row.itemID or 0) or 0, row.slotid, row.slotname, row.itemName)
                else
                    ok = swap_to_bot(row.bot, tonumber(row.itemID or 0) or 0, row.slotid, row.slotname, row.itemName)
                end
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
                if row.isMainChar then
                    ImGui.SetTooltip('Swap this item to your ' .. (row.slotname or 'slot'))
                else
                    ImGui.SetTooltip('Note: Bot decides actual equip slot; weapons often equip to Primary if eligible')
                end
            end

            ImGui.PopID()
        end
    end

    -- Separate main character rows from bot rows
    local mainCharRows = {}
    local botRows = {}
    for _, row in ipairs(U._candidates or {}) do
        local displayRow = build_display_row(row)
        if row.isMainChar then
            table.insert(mainCharRows, displayRow)
        else
            table.insert(botRows, displayRow)
        end
    end

    -- Display main character table first (if any)
    if #mainCharRows > 0 then
        ImGui.TextColored(0.9, 0.8, 0.2, 1.0, 'Your Character:')
        if ImGui.BeginTable('EmuBotUpgradeTableMainChar', numCols,
                ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable) then
            ImGui.TableSetupColumn('Character', ImGuiTableColumnFlags.WidthFixed, 120)
            ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 60)
            ImGui.TableSetupColumn('Slot', ImGuiTableColumnFlags.WidthFixed, 120)
            
            if isWeapon then
                ImGui.TableSetupColumn('Dmg', ImGuiTableColumnFlags.WidthFixed, 60)
                ImGui.TableSetupColumn('Delay', ImGuiTableColumnFlags.WidthFixed, 70)
            end

            ImGui.TableSetupColumn('AC', ImGuiTableColumnFlags.WidthFixed, 60)
            ImGui.TableSetupColumn('HP', ImGuiTableColumnFlags.WidthFixed, 60)
            ImGui.TableSetupColumn('Mana', ImGuiTableColumnFlags.WidthFixed, 70)

            if U._show_advanced_stats then
                -- Core stat columns
                ImGui.TableSetupColumn('STR', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('DEX', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('AGI', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('STA', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('INT', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('WIS', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('CHA', ImGuiTableColumnFlags.WidthFixed, 50)

                -- Heroic stat columns
                ImGui.TableSetupColumn('hSTR', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hDEX', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hAGI', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hSTA', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hINT', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hWIS', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hCHA', ImGuiTableColumnFlags.WidthFixed, 50)

                -- Resist columns
                ImGui.TableSetupColumn('svM', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svF', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svC', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svP', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svD', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svCor', ImGuiTableColumnFlags.WidthFixed, 50)
            end

            ImGui.TableSetupColumn('Action', ImGuiTableColumnFlags.WidthFixed, 120)
            ImGui.TableHeadersRow()

            render_table_rows(mainCharRows, 0)
            ImGui.EndTable()
        end
        ImGui.Spacing()
    end

    -- Display bot table (if any)
    if #botRows > 0 then
        if #mainCharRows > 0 then
            ImGui.TextColored(0.7, 0.9, 1.0, 1.0, 'Bots:')
        end
        if ImGui.BeginTable('EmuBotUpgradeTableBots', numCols,
                ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.Sortable) then
            ImGui.TableSetupColumn('Bot', ImGuiTableColumnFlags.WidthFixed, 120)
            ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 60)
            ImGui.TableSetupColumn('Slot', ImGuiTableColumnFlags.WidthFixed, 120)

            if isWeapon then
                ImGui.TableSetupColumn('Dmg', ImGuiTableColumnFlags.WidthFixed, 60)
                ImGui.TableSetupColumn('Delay', ImGuiTableColumnFlags.WidthFixed, 70)
            end

            ImGui.TableSetupColumn('AC', ImGuiTableColumnFlags.WidthFixed, 60)
            ImGui.TableSetupColumn('HP', ImGuiTableColumnFlags.WidthFixed, 60)
            ImGui.TableSetupColumn('Mana', ImGuiTableColumnFlags.WidthFixed, 70)

            if U._show_advanced_stats then
                -- Core stat columns
                ImGui.TableSetupColumn('STR', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('DEX', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('AGI', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('STA', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('INT', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('WIS', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('CHA', ImGuiTableColumnFlags.WidthFixed, 50)

                -- Heroic stat columns
                ImGui.TableSetupColumn('hSTR', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hDEX', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hAGI', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hSTA', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hINT', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hWIS', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('hCHA', ImGuiTableColumnFlags.WidthFixed, 50)

                -- Resist columns
                ImGui.TableSetupColumn('svM', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svF', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svC', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svP', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svD', ImGuiTableColumnFlags.WidthFixed, 50)
                ImGui.TableSetupColumn('svCor', ImGuiTableColumnFlags.WidthFixed, 50)
            end

            ImGui.TableSetupColumn('Action', ImGuiTableColumnFlags.WidthFixed, 120)
            ImGui.TableHeadersRow()

            local sortAccessors
            if isWeapon and U._show_advanced_stats then
                sortAccessors = {
                    [1] = function(entry) return entry.ref.bot or '' end,
                    [2] = function(entry) return entry.ref.class or '' end,
                    [3] = function(entry) return entry.slotname or '' end,
                    [4] = function(entry) return entry.deltaDamage or 0 end,
                    [5] = function(entry) return entry.deltaDelay or 0 end,
                    [6] = function(entry) return entry.deltaAC or 0 end,
                    [7] = function(entry) return entry.deltaHP or 0 end,
                    [8] = function(entry) return entry.deltaMana or 0 end,
                    [9] = function(entry) return entry.deltaSTR or 0 end,
                    [10] = function(entry) return entry.deltaDEX or 0 end,
                    [11] = function(entry) return entry.deltaAGI or 0 end,
                    [12] = function(entry) return entry.deltaSTA or 0 end,
                    [13] = function(entry) return entry.deltaINT or 0 end,
                    [14] = function(entry) return entry.deltaWIS or 0 end,
                    [15] = function(entry) return entry.deltaCHA or 0 end,
                    [16] = function(entry) return entry.deltaHSTR or 0 end,
                    [17] = function(entry) return entry.deltaHDEX or 0 end,
                    [18] = function(entry) return entry.deltaHAGI or 0 end,
                    [19] = function(entry) return entry.deltaHSTA or 0 end,
                    [20] = function(entry) return entry.deltaHINT or 0 end,
                    [21] = function(entry) return entry.deltaHWIS or 0 end,
                    [22] = function(entry) return entry.deltaHCHA or 0 end,
                    [23] = function(entry) return entry.deltaSvMagic or 0 end,
                    [24] = function(entry) return entry.deltaSvFire or 0 end,
                    [25] = function(entry) return entry.deltaSvCold or 0 end,
                    [26] = function(entry) return entry.deltaSvPoison or 0 end,
                    [27] = function(entry) return entry.deltaSvDisease or 0 end,
                    [28] = function(entry) return entry.deltaSvCorruption or 0 end,
                }
            elseif isWeapon then
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
            elseif U._show_advanced_stats then
                sortAccessors = {
                    [1] = function(entry) return entry.ref.bot or '' end,
                    [2] = function(entry) return entry.ref.class or '' end,
                    [3] = function(entry) return entry.slotname or '' end,
                    [4] = function(entry) return entry.deltaAC or 0 end,
                    [5] = function(entry) return entry.deltaHP or 0 end,
                    [6] = function(entry) return entry.deltaMana or 0 end,
                    [7] = function(entry) return entry.deltaSTR or 0 end,
                    [8] = function(entry) return entry.deltaDEX or 0 end,
                    [9] = function(entry) return entry.deltaAGI or 0 end,
                    [10] = function(entry) return entry.deltaSTA or 0 end,
                    [11] = function(entry) return entry.deltaINT or 0 end,
                    [12] = function(entry) return entry.deltaWIS or 0 end,
                    [13] = function(entry) return entry.deltaCHA or 0 end,
                    [14] = function(entry) return entry.deltaHSTR or 0 end,
                    [15] = function(entry) return entry.deltaHDEX or 0 end,
                    [16] = function(entry) return entry.deltaHAGI or 0 end,
                    [17] = function(entry) return entry.deltaHSTA or 0 end,
                    [18] = function(entry) return entry.deltaHINT or 0 end,
                    [19] = function(entry) return entry.deltaHWIS or 0 end,
                    [20] = function(entry) return entry.deltaHCHA or 0 end,
                    [21] = function(entry) return entry.deltaSvMagic or 0 end,
                    [22] = function(entry) return entry.deltaSvFire or 0 end,
                    [23] = function(entry) return entry.deltaSvCold or 0 end,
                    [24] = function(entry) return entry.deltaSvPoison or 0 end,
                    [25] = function(entry) return entry.deltaSvDisease or 0 end,
                    [26] = function(entry) return entry.deltaSvCorruption or 0 end,
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
            applyTableSort(botRows, ImGui.TableGetSortSpecs(), sortAccessors)

            render_table_rows(botRows, #mainCharRows)
            ImGui.EndTable()
        end
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
    -- Skip if this is the main character (we add them separately)
    if is_main_char_name(name) then return end

    local itemID = tonumber(mq.TLO.Cursor.ID() or 0) or 0
    local itemName = mq.TLO.Cursor.Name() or 'Item'
    local sid, sname = slot_from_phrase(slotPhrase)
    if not sid then return end

    -- Check level requirement
    local cur = mq.TLO.Cursor
    if cur and cur() then
        local requiredLevel = tonumber(cur.RequiredLevel() or 0) or 0
        local botLevel = 0
        if bot_inventory and bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[name] then
            botLevel = tonumber(bot_inventory.bot_list_capture_set[name].Level or 0) or 0
        end
        if requiredLevel > botLevel and botLevel > 0 then
            U._level_too_low = true
            return  -- Bot level too low for this item
        end
    end

    -- Get bot class from metadata if available
    local botClass = 'UNK'
    if bot_inventory and bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[name] then
        botClass = bot_inventory.bot_list_capture_set[name].Class or 'UNK'
    end
    local classAbbrev = extract_class_abbreviation(botClass)

    add_candidate({ bot = name, class = classAbbrev, slotid = sid, slotname = sname, itemID = itemID, itemName = itemName, isMainChar = false })
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
    local upgAllStats = U._show_advanced_stats and get_cursor_all_stats() or {}

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
    ImGui.SameLine()
    U._show_advanced_stats = ImGui.Checkbox('Advanced Stats##upgradeCompare', U._show_advanced_stats)
    ImGui.Separator()

    if #U._candidates == 0 then
        if U._level_too_low then
            ImGui.TextColored(0.9, 0.5, 0.2, 1.0, 'Item Required Level Exceeds Current Level')
        else
            ImGui.Text('No candidates to compare.')
        end
        ImGui.End()
        return
    end

    -- Determine number of columns based on whether the item is a weapon (removed Upgrade column)
    local numCols = isWeapon and 10 or 8

    -- Add additional columns if advanced stats are enabled
    if U._show_advanced_stats then
        numCols = numCols + 20  -- +7 core stats, +7 heroic stats, +6 resists
    end

    local compareRows = {}
    for _, row in ipairs(U._candidates or {}) do
        local curItem = nil
        local cAC, cHP, cMana, cDamage, cDelay = 0, 0, 0, 0, 0
        local curAllStats = {}

        if row.isMainChar then
            local equippedItem = nil
            if row.slotid ~= nil then
                equippedItem = mq.TLO.Me.Inventory(row.slotid)
            end
            if equippedItem and equippedItem() then
                cAC = tonumber(equippedItem.AC() or 0) or 0
                cHP = tonumber(equippedItem.HP() or 0) or 0
                cMana = tonumber(equippedItem.Mana() or 0) or 0
                cDamage = tonumber(equippedItem.Damage() or 0) or 0
                cDelay = tonumber(equippedItem.ItemDelay() or 0) or 0

                -- Get all stats if advanced mode is enabled
                if U._show_advanced_stats then
                    curAllStats = get_item_all_stats(equippedItem)
                end

                local clickable, raw = nil, nil
                if equippedItem.ItemLink then
                    local okClickable, linkClickable = pcall(function() return equippedItem.ItemLink('CLICKABLE')() end)
                    if okClickable and linkClickable and linkClickable ~= '' then clickable = linkClickable end
                    local okRaw, linkRaw = pcall(function() return equippedItem.ItemLink('RAW')() end)
                    if okRaw and linkRaw and linkRaw ~= '' then raw = linkRaw end
                end

                curItem = {
                    name = equippedItem.Name() or '',
                    ac = cAC,
                    hp = cHP,
                    mana = cMana,
                    damage = cDamage,
                    delay = cDelay,
                    itemlink = clickable,
                    itemlink_raw = raw,
                }
            end
        elseif bot_inventory and bot_inventory.getBotEquippedItem and row.bot and row.slotid ~= nil then
            curItem = bot_inventory.getBotEquippedItem(row.bot, row.slotid)
            cAC = tonumber(curItem and curItem.ac or 0) or 0
            cHP = tonumber(curItem and curItem.hp or 0) or 0
            cMana = tonumber(curItem and curItem.mana or 0) or 0
            cDamage = tonumber(curItem and curItem.damage or 0) or 0
            cDelay = tonumber(curItem and curItem.delay or 0) or 0

            if isWeapon and curItem and curItem.name and (cDamage == 0 and cDelay == 0) then
                local currentItemTLO = mq.TLO.FindItem(string.format('= %s', curItem.name or ''))
                if currentItemTLO and currentItemTLO() then
                    cDamage = tonumber(currentItemTLO.Damage() or 0) or 0
                    cDelay = tonumber(currentItemTLO.ItemDelay() or 0) or 0
                end
            end

            -- Get all stats if advanced mode is enabled
            if U._show_advanced_stats and curItem and curItem.name then
                local currentItemTLO = mq.TLO.FindItem(string.format('= %s', curItem.name or ''))
                if currentItemTLO and currentItemTLO() then
                    curAllStats = get_item_all_stats(currentItemTLO)
                end
            end
        end

        if U._show_advanced_stats and next(curAllStats) == nil and curItem then
            curAllStats = get_cached_item_all_stats(curItem)
        end

        local compareEntry = {
            ref = row,
            stats = {
                item = curItem,
                ac = cAC,
                hp = cHP,
                mana = cMana,
                damage = cDamage,
                delay = cDelay,
            },
        }

        -- Add advanced stat deltas if enabled
        if U._show_advanced_stats then
            compareEntry.deltaSTR = (upgAllStats.str or 0) - (curAllStats.str or 0)
            compareEntry.deltaDEX = (upgAllStats.dex or 0) - (curAllStats.dex or 0)
            compareEntry.deltaAGI = (upgAllStats.agi or 0) - (curAllStats.agi or 0)
            compareEntry.deltaSTA = (upgAllStats.sta or 0) - (curAllStats.sta or 0)
            compareEntry.deltaINT = (upgAllStats.int or 0) - (curAllStats.int or 0)
            compareEntry.deltaWIS = (upgAllStats.wis or 0) - (curAllStats.wis or 0)
            compareEntry.deltaCHA = (upgAllStats.cha or 0) - (curAllStats.cha or 0)

            compareEntry.deltaHSTR = (upgAllStats.heroicStr or 0) - (curAllStats.heroicStr or 0)
            compareEntry.deltaHDEX = (upgAllStats.heroicDex or 0) - (curAllStats.heroicDex or 0)
            compareEntry.deltaHAGI = (upgAllStats.heroicAgi or 0) - (curAllStats.heroicAgi or 0)
            compareEntry.deltaHSTA = (upgAllStats.heroicSta or 0) - (curAllStats.heroicSta or 0)
            compareEntry.deltaHINT = (upgAllStats.heroicInt or 0) - (curAllStats.heroicInt or 0)
            compareEntry.deltaHWIS = (upgAllStats.heroicWis or 0) - (curAllStats.heroicWis or 0)
            compareEntry.deltaHCHA = (upgAllStats.heroicCha or 0) - (curAllStats.heroicCha or 0)

            compareEntry.deltaSvMagic = (upgAllStats.svMagic or 0) - (curAllStats.svMagic or 0)
            compareEntry.deltaSvFire = (upgAllStats.svFire or 0) - (curAllStats.svFire or 0)
            compareEntry.deltaSvCold = (upgAllStats.svCold or 0) - (curAllStats.svCold or 0)
            compareEntry.deltaSvPoison = (upgAllStats.svPoison or 0) - (curAllStats.svPoison or 0)
            compareEntry.deltaSvDisease = (upgAllStats.svDisease or 0) - (curAllStats.svDisease or 0)
            compareEntry.deltaSvCorruption = (upgAllStats.svCorruption or 0) - (curAllStats.svCorruption or 0)
        end

        table.insert(compareRows, compareEntry)
    end

    local compareMainRows, compareBotRows = {}, {}
    for _, entry in ipairs(compareRows) do
        if entry.ref.isMainChar then
            table.insert(compareMainRows, entry)
        else
            table.insert(compareBotRows, entry)
        end
    end

    local function setup_compare_columns()
        ImGui.TableSetupColumn('Character', ImGuiTableColumnFlags.WidthFixed, 120)
        ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('Slot', ImGuiTableColumnFlags.WidthFixed, 120)
        ImGui.TableSetupColumn('Current', ImGuiTableColumnFlags.WidthStretch)
        if isWeapon then
            ImGui.TableSetupColumn('Dmg', ImGuiTableColumnFlags.WidthFixed, 60)
            ImGui.TableSetupColumn('Delay', ImGuiTableColumnFlags.WidthFixed, 70)
        end
        ImGui.TableSetupColumn('AC', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('HP', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('Mana', ImGuiTableColumnFlags.WidthFixed, 70)

        if U._show_advanced_stats then
            -- Core stat columns
            ImGui.TableSetupColumn('STR', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('DEX', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('AGI', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('STA', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('INT', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('WIS', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('CHA', ImGuiTableColumnFlags.WidthFixed, 50)

            -- Heroic stat columns
            ImGui.TableSetupColumn('hSTR', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('hDEX', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('hAGI', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('hSTA', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('hINT', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('hWIS', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('hCHA', ImGuiTableColumnFlags.WidthFixed, 50)

            -- Resist columns
            ImGui.TableSetupColumn('svM', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('svF', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('svC', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('svP', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('svD', ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn('svCor', ImGuiTableColumnFlags.WidthFixed, 50)
        end

        ImGui.TableSetupColumn('Action', ImGuiTableColumnFlags.WidthFixed, 90)
        ImGui.TableHeadersRow()
    end

    local function sort_specs(rows)
        if not rows or #rows == 0 then return end
        local specs = ImGui.TableGetSortSpecs()
        if not specs or not specs.SpecsCount or specs.SpecsCount == 0 then return end
        if isWeapon and U._show_advanced_stats then
            applyTableSort(rows, specs, {
                [1] = function(entry) return entry.ref.bot or '' end,
                [2] = function(entry) return entry.ref.class or '' end,
                [3] = function(entry) return entry.ref.slotname or ('Slot ' .. tostring(entry.ref.slotid or '?')) end,
                [4] = function(entry) return entry.stats.item and entry.stats.item.name or '' end,
                [5] = function(entry) return (upgDamage or 0) - (entry.stats.damage or 0) end,
                [6] = function(entry) return (upgDelay or 0) - (entry.stats.delay or 0) end,
                [7] = function(entry) return (upgAC or 0) - (entry.stats.ac or 0) end,
                [8] = function(entry) return (upgHP or 0) - (entry.stats.hp or 0) end,
                [9] = function(entry) return (upgMana or 0) - (entry.stats.mana or 0) end,
                [10] = function(entry) return entry.deltaSTR or 0 end,
                [11] = function(entry) return entry.deltaDEX or 0 end,
                [12] = function(entry) return entry.deltaAGI or 0 end,
                [13] = function(entry) return entry.deltaSTA or 0 end,
                [14] = function(entry) return entry.deltaINT or 0 end,
                [15] = function(entry) return entry.deltaWIS or 0 end,
                [16] = function(entry) return entry.deltaCHA or 0 end,
                [17] = function(entry) return entry.deltaHSTR or 0 end,
                [18] = function(entry) return entry.deltaHDEX or 0 end,
                [19] = function(entry) return entry.deltaHAGI or 0 end,
                [20] = function(entry) return entry.deltaHSTA or 0 end,
                [21] = function(entry) return entry.deltaHINT or 0 end,
                [22] = function(entry) return entry.deltaHWIS or 0 end,
                [23] = function(entry) return entry.deltaHCHA or 0 end,
                [24] = function(entry) return entry.deltaSvMagic or 0 end,
                [25] = function(entry) return entry.deltaSvFire or 0 end,
                [26] = function(entry) return entry.deltaSvCold or 0 end,
                [27] = function(entry) return entry.deltaSvPoison or 0 end,
                [28] = function(entry) return entry.deltaSvDisease or 0 end,
                [29] = function(entry) return entry.deltaSvCorruption or 0 end,
            })
        elseif isWeapon then
            applyTableSort(rows, specs, {
                [1] = function(entry) return entry.ref.bot or '' end,
                [2] = function(entry) return entry.ref.class or '' end,
                [3] = function(entry) return entry.ref.slotname or ('Slot ' .. tostring(entry.ref.slotid or '?')) end,
                [4] = function(entry) return entry.stats.item and entry.stats.item.name or '' end,
                [5] = function(entry) return (upgDamage or 0) - (entry.stats.damage or 0) end,
                [6] = function(entry) return (upgDelay or 0) - (entry.stats.delay or 0) end,
                [7] = function(entry) return (upgAC or 0) - (entry.stats.ac or 0) end,
                [8] = function(entry) return (upgHP or 0) - (entry.stats.hp or 0) end,
                [9] = function(entry) return (upgMana or 0) - (entry.stats.mana or 0) end,
            })
        elseif U._show_advanced_stats then
            applyTableSort(rows, specs, {
                [1] = function(entry) return entry.ref.bot or '' end,
                [2] = function(entry) return entry.ref.class or '' end,
                [3] = function(entry) return entry.ref.slotname or ('Slot ' .. tostring(entry.ref.slotid or '?')) end,
                [4] = function(entry) return entry.stats.item and entry.stats.item.name or '' end,
                [5] = function(entry) return (upgAC or 0) - (entry.stats.ac or 0) end,
                [6] = function(entry) return (upgHP or 0) - (entry.stats.hp or 0) end,
                [7] = function(entry) return (upgMana or 0) - (entry.stats.mana or 0) end,
                [8] = function(entry) return entry.deltaSTR or 0 end,
                [9] = function(entry) return entry.deltaDEX or 0 end,
                [10] = function(entry) return entry.deltaAGI or 0 end,
                [11] = function(entry) return entry.deltaSTA or 0 end,
                [12] = function(entry) return entry.deltaINT or 0 end,
                [13] = function(entry) return entry.deltaWIS or 0 end,
                [14] = function(entry) return entry.deltaCHA or 0 end,
                [15] = function(entry) return entry.deltaHSTR or 0 end,
                [16] = function(entry) return entry.deltaHDEX or 0 end,
                [17] = function(entry) return entry.deltaHAGI or 0 end,
                [18] = function(entry) return entry.deltaHSTA or 0 end,
                [19] = function(entry) return entry.deltaHINT or 0 end,
                [20] = function(entry) return entry.deltaHWIS or 0 end,
                [21] = function(entry) return entry.deltaHCHA or 0 end,
                [22] = function(entry) return entry.deltaSvMagic or 0 end,
                [23] = function(entry) return entry.deltaSvFire or 0 end,
                [24] = function(entry) return entry.deltaSvCold or 0 end,
                [25] = function(entry) return entry.deltaSvPoison or 0 end,
                [26] = function(entry) return entry.deltaSvDisease or 0 end,
                [27] = function(entry) return entry.deltaSvCorruption or 0 end,
            })
        else
            applyTableSort(rows, specs, {
                [1] = function(entry) return entry.ref.bot or '' end,
                [2] = function(entry) return entry.ref.class or '' end,
                [3] = function(entry) return entry.ref.slotname or ('Slot ' .. tostring(entry.ref.slotid or '?')) end,
                [4] = function(entry) return entry.stats.item and entry.stats.item.name or '' end,
                [5] = function(entry) return (upgAC or 0) - (entry.stats.ac or 0) end,
                [6] = function(entry) return (upgHP or 0) - (entry.stats.hp or 0) end,
                [7] = function(entry) return (upgMana or 0) - (entry.stats.mana or 0) end,
            })
        end
    end

    local closeAfterSwap = false

    local function render_compare_rows(rows, idPrefix)
        local function color_damage(delta)
            if delta > 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, '+' .. tostring(delta))
            elseif delta < 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(delta))
            else ImGui.Text('0') end
        end
        local function color_delay(delta)
            if delta < 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, tostring(delta))
            elseif delta > 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, '+' .. tostring(delta))
            else ImGui.Text('0') end
        end
        local function colortext(delta)
            if delta > 0 then ImGui.TextColored(0.0, 0.9, 0.0, 1.0, '+' .. tostring(delta))
            elseif delta < 0 then ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(delta))
            else ImGui.Text('0') end
        end

        for i, entry in ipairs(rows) do
            local row = entry.ref
            local stats = entry.stats
            ImGui.TableNextRow()
            ImGui.PushID(string.format('%s_%d', idPrefix, i))

            local curItem = stats.item
            local dAC = (upgAC or 0) - (stats.ac or 0)
            local dHP = (upgHP or 0) - (stats.hp or 0)
            local dMana = (upgMana or 0) - (stats.mana or 0)
            local dDamage = (upgDamage or 0) - (stats.damage or 0)
            local dDelay = (upgDelay or 0) - (stats.delay or 0)

            ImGui.TableNextColumn()
            local selectableLabel = (row.bot or 'Unknown') .. '##target_' .. string.format('%s_%d', idPrefix, i)
            if ImGui.Selectable(selectableLabel, false, ImGuiSelectableFlags.None) then
                if not row.isMainChar then
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
            end
            if ImGui.IsItemHovered() then
                if row.isMainChar then
                    ImGui.SetTooltip('This is you')
                else
                    ImGui.SetTooltip('Click to target ' .. (row.bot or 'bot'))
                end
            end

            ImGui.TableNextColumn(); ImGui.Text(row.class or 'UNK')
            ImGui.TableNextColumn(); ImGui.Text(row.slotname or ('Slot ' .. tostring(row.slotid or '?')))

            ImGui.TableNextColumn()
            if curItem and curItem.name and curItem.name ~= '' then
                if curItem.itemlink and curItem.itemlink ~= '' then
                    local links = mq.ExtractLinks(curItem.itemlink)
                    if links and #links > 0 then
                        if ImGui.Selectable(curItem.name, false, ImGuiSelectableFlags.None) then
                            if mq.ExecuteTextLink then
                                mq.ExecuteTextLink(links[1])
                            end
                        end
                        if ImGui.IsItemHovered() then ImGui.SetTooltip('Click to inspect current item') end
                    else
                        ImGui.Text(curItem.name)
                    end
                else
                    ImGui.Text(curItem.name)
                end
            else
                ImGui.Text('--')
            end

            if isWeapon then
                ImGui.TableNextColumn(); color_damage(dDamage)
                ImGui.TableNextColumn(); color_delay(dDelay)
            end

            ImGui.TableNextColumn(); colortext(dAC)
            ImGui.TableNextColumn(); colortext(dHP)
            ImGui.TableNextColumn(); colortext(dMana)

            -- Advanced stat deltas (if enabled)
            if U._show_advanced_stats then
                -- Core stats
                ImGui.TableNextColumn(); colortext(entry.deltaSTR)
                ImGui.TableNextColumn(); colortext(entry.deltaDEX)
                ImGui.TableNextColumn(); colortext(entry.deltaAGI)
                ImGui.TableNextColumn(); colortext(entry.deltaSTA)
                ImGui.TableNextColumn(); colortext(entry.deltaINT)
                ImGui.TableNextColumn(); colortext(entry.deltaWIS)
                ImGui.TableNextColumn(); colortext(entry.deltaCHA)

                -- Heroic stats
                ImGui.TableNextColumn(); colortext(entry.deltaHSTR)
                ImGui.TableNextColumn(); colortext(entry.deltaHDEX)
                ImGui.TableNextColumn(); colortext(entry.deltaHAGI)
                ImGui.TableNextColumn(); colortext(entry.deltaHSTA)
                ImGui.TableNextColumn(); colortext(entry.deltaHINT)
                ImGui.TableNextColumn(); colortext(entry.deltaHWIS)
                ImGui.TableNextColumn(); colortext(entry.deltaHCHA)

                -- Resists
                ImGui.TableNextColumn(); colortext(entry.deltaSvMagic)
                ImGui.TableNextColumn(); colortext(entry.deltaSvFire)
                ImGui.TableNextColumn(); colortext(entry.deltaSvCold)
                ImGui.TableNextColumn(); colortext(entry.deltaSvPoison)
                ImGui.TableNextColumn(); colortext(entry.deltaSvDisease)
                ImGui.TableNextColumn(); colortext(entry.deltaSvCorruption)
            end

            ImGui.TableNextColumn()
            local swapped = false
            if ImGui.SmallButton('Swap##cmp_' .. string.format('%s_%d', idPrefix, i)) then
                local ok
                if row.isMainChar then
                    ok = swap_to_main_char(tonumber(row.itemID or 0) or 0, row.slotid, row.slotname, row.itemName)
                else
                    ok = swap_to_bot(row.bot, tonumber(row.itemID or 0) or 0, row.slotid, row.slotname, row.itemName)
                end
                if ok then
                    for idx, candidate in ipairs(U._candidates) do
                        if candidate == row then
                            table.remove(U._candidates, idx)
                            break
                        end
                    end
                    swapped = true
                    closeAfterSwap = true
                end
            end
            if ImGui.IsItemHovered() then
                if row.isMainChar then
                    ImGui.SetTooltip('Swap this item to your ' .. (row.slotname or 'slot'))
                else
                    ImGui.SetTooltip('Note: Bot decides actual equip slot; weapons often equip to Primary if eligible')
                end
            end

            ImGui.PopID()
            if swapped then return true end
        end
        return false
    end

    if #compareMainRows > 0 then
        ImGui.TextColored(0.9, 0.8, 0.2, 1.0, 'Your Character:')
        if ImGui.BeginTable('EmuBotUpgradeCompareMain', numCols,
                ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable) then
            setup_compare_columns()
            render_compare_rows(compareMainRows, 'main')
            ImGui.EndTable()
        end
        ImGui.Spacing()
    end

    if #compareBotRows > 0 then
        if #compareMainRows > 0 then
            ImGui.TextColored(0.7, 0.9, 1.0, 1.0, 'Bots:')
        end
        if ImGui.BeginTable('EmuBotUpgradeCompareBots', numCols,
                ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.Sortable) then
            setup_compare_columns()
            sort_specs(compareBotRows)
            if render_compare_rows(compareBotRows, 'bot') then
                closeAfterSwap = true
            end
            ImGui.EndTable()
        end
    end

    if closeAfterSwap and U._close_window_on_swap then
        U._show_compare = false
        ImGui.End()
        return
    end

    ImGui.End()
end

return U
