local mq = require('mq')
local ImGui = require('ImGui')
local bot_inventory = require('EmuBot.modules.bot_inventory')

local M = {
    show = false,
    _spellPrompt = nil,
    _activeTab = 1, -- 1 = Bot Controls, 2 = Quick Settings
    _botStances = {}, -- Track current stance for each bot
    _individualBotWindows = {}, -- Track open individual bot windows
    _showClassNames = false, -- Toggle between showing bot names (false) or class names (true)
    -- Learned spells cache per-bot (from ^spells)
    _botLearnedSpells = {}, -- [botName] = { loading=true/false, entries = { {index=#, id=####, name='..'} } }
    _collectingSpellsForBot = nil, -- botName currently being collected
    _spellEventsRegistered = false,
    _addSpellPrompt = nil, -- modal for adding a learned spell with args
    _debugSpells = false,
    _spellCategoryCache = {},
    -- Batch commands state
    _batch = {
        groups = {},
        selected = nil,
        newGroupName = '',
        commandText = '',
        includeSpawnedOnly = true,
        queueDelayMs = 75,
        filterText = '',
    },
}

-- Stance mapping table
local stanceMap = {
    [1] = "Passive",
    [2] = "Balanced", 
    [3] = "Efficient",
    [4] = "Reactive",
    [5] = "Aggressive",
    [6] = "Assist",
    [7] = "Burn",
    [8] = "Efficient", -- Efficient2 shows as "Efficient"
    [9] = "AE Burn"
}

local function _getStanceName(stanceNum)
    return stanceMap[stanceNum] or "Unknown"
end

local function _getBotStance(botName)
    return M._botStances[botName] or "Unknown"
end

-- Create dropdown options for stances
local stanceDropdownOptions = {
    "Passive (1)",
    "Balanced (2)", 
    "Efficient (3)",
    "Reactive (4)",
    "Aggressive (5)",
    "Assist (6)",
    "Burn (7)",
    "Efficient Alt (8)",
    "AE Burn (9)"
}

local function _getStanceDropdownIndex(botName)
    local stanceText = _getBotStance(botName)
    -- Extract stance number from text like "Balanced (2)"
    local stanceNum = stanceText:match("%((%d+)%)") 
    if stanceNum then
        return tonumber(stanceNum) or 1
    end
    return 1 -- Default to Passive
end

local function _setBotStance(botName, stanceNum, stanceName)
    if stanceNum then
        M._botStances[botName] = string.format("%s (%d)", stanceName or _getStanceName(stanceNum), stanceNum)
    else
        M._botStances[botName] = stanceName or "Unknown"
    end
end

local function _enqueue(fn)
    if _G.enqueueTask then _G.enqueueTask(fn) else fn() end
end

local function _targetBotByName(botName)
    local s = mq.TLO.Spawn(string.format('= %s', botName))
    if s and s.ID and s.ID() and s.ID() > 0 then
        mq.cmdf('/target id %d', s.ID())
    else
        mq.cmdf('/target "%s"', botName)
    end
end

local function _runForBot(botName, caretCommandWithTarget)
    _targetBotByName(botName)
    _enqueue(function()
        mq.delay(150)
        mq.cmd(string.format('/say %s', caretCommandWithTarget))
    end)
end

local function _runQuickCommand(command)
    _enqueue(function()
        mq.cmd(command)
    end)
end

local function _runQuickSayCommand(sayCommand)
    _enqueue(function()
        mq.cmd(string.format('/say %s', sayCommand))
    end)
end

-- Layout helper: 3 buttons per row within a section
local _row3 = {count = 0, spacingY = 6}
local function _row3_reset()
    _row3.count = 0
end
local function _row3_set_spacing(y)
    _row3.spacingY = tonumber(y) or _row3.spacingY
end
local function _button3(label, width, tooltip, on_click)
    if ImGui.Button(label, width or 120, 0) then
        if on_click then on_click() end
    end
    if tooltip and ImGui.IsItemHovered() then
        ImGui.SetTooltip(tooltip)
    end
    _row3.count = _row3.count + 1
    if (_row3.count % 3) ~= 0 then
        ImGui.SameLine()
    else
        -- add vertical spacing between rows
        ImGui.Dummy(0, _row3.spacingY)
    end
end

-- Event handler for bot stance responses
local function _handleBotStanceResponse(line, botName, stanceName, stanceNumber)
    if botName and stanceName and stanceNumber then
        local stanceNum = tonumber(stanceNumber)
        if stanceNum then
            _setBotStance(botName, stanceNum, stanceName)
        end
    end
end


-- Register the MQ2 chat event for bot stance responses
-- This captures messages like "BotName says, 'My current stance is Balanced (2).'"
local stanceEventRegistered = false

local function _registerStanceEvent()
    if not stanceEventRegistered then
        -- Register multiple patterns to catch different response formats
        mq.event("BotStanceResponse1", "#1# says, 'My current stance is #2# (#3#).'", _handleBotStanceResponse)
        mq.event("BotStanceResponse2", "#1# says, 'My current stance is #2#(#3#).'", _handleBotStanceResponse)
        mq.event("BotStanceResponse3", "#1# says 'My current stance is #2# (#3#).'", _handleBotStanceResponse)
        
        stanceEventRegistered = true
        print("[BotControls] Stance event handlers registered")
    end
end

local function _unregisterStanceEvent()
    if stanceEventRegistered then
        mq.unevent("BotStanceResponse1")
        mq.unevent("BotStanceResponse2")
        mq.unevent("BotStanceResponse3")
        stanceEventRegistered = false
        print("[BotControls] Stance event handlers unregistered")
    end
end

-- Spells (^spells) parsing
local function _ensureBotSpellStore(botName)
    M._botLearnedSpells[botName] = M._botLearnedSpells[botName] or {loading=false, entries={}, updated=os.time()}
    return M._botLearnedSpells[botName]
end

local function _sanitizeLinkText(txt)
    -- Basic cleanup for MQ link wrappers if present
    txt = tostring(txt or '')
    -- Remove color/link control codes if they appear, keep readable name
    txt = txt:gsub("%c", "")
    return txt
end

local function _addLearnedSpell(botName, idx, name, id)
    local store = _ensureBotSpellStore(botName)
    local entries = store.entries
    -- Prevent duplicates by id
    local found = false
    for _, e in ipairs(entries) do
        if tonumber(e.id) == tonumber(id) then
            e.index = idx or e.index
            e.name = name or e.name
            found = true
            break
        end
    end
    if not found then
        table.insert(entries, {index=tonumber(idx) or 0, id=tonumber(id) or 0, name=tostring(name or '')})
    end
    store.updated = os.time()
end

-- Resolve spell ID from a spell name/link via MQ TLO
local function _resolveSpellIdByName(name)
    local id = 0
    local ok, result = pcall(function()
        local s = mq.TLO.Spell(tostring(name or ''))
        if s and s() and s.ID then
            return tonumber(s.ID()) or 0
        end
        return 0
    end)
    if ok and result and tonumber(result) then
        id = tonumber(result)
    end
    return id
end

local function _getServerName()
    local ok, server = pcall(function()
        return mq.TLO.EverQuest and mq.TLO.EverQuest.Server and mq.TLO.EverQuest.Server()
    end)
    if ok and server then return tostring(server) end
    return ''
end

local function _handleSpellsTokens(line, idxToken, spellNameToken, idToken, addToken)
    local botName = M._collectingSpellsForBot
    if not botName or botName == '' then return end
    -- Extract index number from token like "Spell 012" or just number
    local idx = tonumber(tostring(idxToken or ''):match('%d+')) or 0
    local name = _sanitizeLinkText(spellNameToken)
    local id = tonumber(idToken) or 0
    if M._debugSpells then
        print(string.format('[BotControls][SpellsEvent] bot=%s idx=%s id=%s name=%s', tostring(botName), tostring(idx), tostring(id), tostring(name)))
    end
    if id > 0 and name ~= '' then
        _addLearnedSpell(botName, idx, name, id)
    end
end

local function _registerSpellEvents()
    if M._spellEventsRegistered then return end
    -- Robust patterns that avoid relying on literal pipes
    -- Full capture: index, name, id
    mq.event("BotSpellsLineFull", "Spell #1# #*# Spell: #2# (ID: #3#) #*#", function(line, idx, name, id)
        _handleSpellsTokens(line, idx, name, id, nil)
    end)
    -- Fallback: name and id only
    mq.event("BotSpellsLineNameId", "#*#Spell: #1# (ID: #2#)#*#", function(line, name, id)
        _handleSpellsTokens(line, 0, name, id, nil)
    end)
    -- Variants when spoken via NPC say
    mq.event("BotSpellsSay1", "#1# says, 'Spell #2# #*# Spell: #3# (ID: #4#) #*#'", function(line, speaker, idx, name, id)
        _handleSpellsTokens(line, idx, name, id, nil)
    end)
    mq.event("BotSpellsSay2", "#1# says 'Spell #2# #*# Spell: #3# (ID: #4#) #*#'", function(line, speaker, idx, name, id)
        _handleSpellsTokens(line, idx, name, id, nil)
    end)
    
    -- VEQ2002 format: "Spell 15 | Spell: <name> | Add Spell: Add"
    -- Very permissive pattern: capture index and name, ignore pipes and trailing text
    mq.event("BotSpellsVEQ", "#*#Spell #1# #*# Spell: #2# #*#", function(line, idxToken, nameToken)
        local botName = M._collectingSpellsForBot
        if not botName or botName == '' then return end
        local idx = tonumber(tostring(idxToken or ''):match('%d+')) or 0
        local name = _sanitizeLinkText(nameToken)
        if name and name ~= '' then
            -- Resolve ID from MQ TLO by name
            local id = _resolveSpellIdByName(name)
            if id > 0 then
                _addLearnedSpell(botName, idx, name, id)
                if M._debugSpells then
                    print(string.format('[BotControls][SpellsEvent-VEQ] bot=%s idx=%d name=%s id=%d', tostring(botName), idx, tostring(name), id))
                end
            end
        end
    end, { keepLinks = true })
    
    -- Fallback minimal format without pipes
    mq.event("BotSpellsMinimal", "#*#Spell #1# #*# Spell: #2#", function(line, idxToken, nameToken)
        local botName = M._collectingSpellsForBot
        if not botName or botName == '' then return end
        local idx = tonumber(tostring(idxToken or ''):match('%d+')) or 0
        local name = _sanitizeLinkText(nameToken)
        if name and name ~= '' then
            local id = _resolveSpellIdByName(name)
            if id > 0 then
                _addLearnedSpell(botName, idx, name, id)
                if M._debugSpells then
                    print(string.format('[BotControls][SpellsEvent-Min] bot=%s idx=%d name=%s id=%d', tostring(botName), idx, tostring(name), id))
                end
            end
        end
    end, { keepLinks = true })
    -- Summary line to mark completion: "{Bot} has {count} AI Spell(s)."
    mq.event("BotSpellsSummary", "#1# has #2# AI Spell#3#.", function(line, bot, count, plural)
        if M._collectingSpellsForBot == bot then
            local store = _ensureBotSpellStore(bot)
            store.loading = false
            M._collectingSpellsForBot = nil
        end
    end)

    -- Optional: debug catch-all to see unmatched lines (enable via M._debugSpells = true)
    if M._debugSpells then
        mq.event("BotSpellsDebug", "#*#Spell:#*#", function(line)
            print("[BotControls][SpellsDebug] Raw line: " .. tostring(line or ""))
        end, { keepLinks = true })
    end

    M._spellEventsRegistered = true
    print("[BotControls] Spell events registered")
end

local function _unregisterSpellEvents()
    if not M._spellEventsRegistered then return end
    mq.unevent("BotSpellsLineFull")
    mq.unevent("BotSpellsLineNameId")
    mq.unevent("BotSpellsSay1")
    mq.unevent("BotSpellsSay2")
    mq.unevent("BotSpellsVEQ")
    mq.unevent("BotSpellsMinimal")
    mq.unevent("BotSpellsSummary")
    mq.unevent("BotSpellsDebug")
    M._spellEventsRegistered = false
    print("[BotControls] Spell events unregistered")
end

-- Categorize spells via MQ Spell TLO
local function _getSpellCategory(spellId)
    if not spellId or tonumber(spellId) == nil or tonumber(spellId) <= 0 then return 'Unknown' end
    if M._spellCategoryCache[spellId] then return M._spellCategoryCache[spellId] end
    local category = 'Unknown'
    local ok, result = pcall(function()
        local s = mq.TLO.Spell(spellId)
        if s and s() and s.Category then
            return s.Category()
        end
        return nil
    end)
    if ok and result and tostring(result) ~= '' then
        category = tostring(result)
    end
    M._spellCategoryCache[spellId] = category
    return category
end

local function _requestBotSpells(botName)
    local store = _ensureBotSpellStore(botName)
    store.entries = {}
    store.loading = true
    store.updated = os.time()
    M._collectingSpellsForBot = botName
    if M._debugSpells then print(string.format('[BotControls] Requesting ^spells for %s', botName)) end
    -- Ask the targeted bot to list learned spells
    _runForBot(botName, '^spells target')
end

-- Get only spawned bots (not just created ones)
local function _getSpawnedBots()
    local spawnedBots = {}
    local allBots = {}
    
    if bot_inventory and bot_inventory.getAllBots then
        allBots = bot_inventory.getAllBots() or {}
    end
    
    -- Check each bot to see if it's actually spawned in the world
    for _, botName in ipairs(allBots) do
        local spawnLookup = mq.TLO.Spawn(string.format("= %s", botName))
        local ok, spawnId = pcall(function()
            return spawnLookup and spawnLookup.ID and spawnLookup.ID()
        end)
        
        if ok and spawnId and spawnId > 0 then
            table.insert(spawnedBots, botName)
        end
    end
    
    return spawnedBots
end

-- Get bot class name
local function _getBotClass(botName)
    local spawnLookup = mq.TLO.Spawn(string.format("= %s", botName))
    local ok, className = pcall(function()
        return spawnLookup and spawnLookup.Class and spawnLookup.Class()
    end)
    
    if ok and className then
        return className
    end
    return "Unknown"
end

-- Compact class abbreviation (for tight lists)
local function _getClassAbbrev(botName)
    local cls = _getBotClass(botName)
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

-- Batch commands helpers
local function _script_dir()
    local info = debug.getinfo(1, 'S')
    local src = info and info.source or ''
    if src:sub(1,1) == '@' then src = src:sub(2) end
    local dir = src:match('^(.*[\\/])')
    return dir or ''
end

local _batch_config_path = _script_dir() .. 'batch_commands.json'
local _has_json, _json = pcall(require, 'EmuBot.dkjson')

local function _batch_load()
    local f = io.open(_batch_config_path, 'r')
    if not f then return false end
    local ok, content = pcall(f.read, f, '*a')
    pcall(f.close, f)
    if not ok or not content or content == '' or not _has_json then return false end
    local decoded, pos, err = _json.decode(content)
    if not decoded or err then return false end
    M._batch.groups = decoded.groups or {}
    M._batch.selected = decoded.selected or nil
    M._batch.queueDelayMs = tonumber(decoded.queueDelayMs or 75) or 75
    return true
end

local function _batch_save()
    if not _has_json then return false end
    local data = {
        groups = M._batch.groups,
        selected = M._batch.selected,
        queueDelayMs = M._batch.queueDelayMs,
    }
    local encoded = _json.encode(data, {indent=true})
    local f = io.open(_batch_config_path, 'w')
    if not f then return false end
    local ok = pcall(f.write, f, encoded)
    pcall(f.close, f)
    return ok and true or false
end

pcall(_batch_load)

-- Function to refresh all bot stances (only for spawned bots)
local function _refreshBotStances()
    local names = _getSpawnedBots()
    
    for _, botName in ipairs(names) do
        _enqueue(function()
            mq.delay(50) -- Small delay between commands
            _targetBotByName(botName)
            mq.delay(100)
            mq.cmd('/say ^stance current target')
        end)
    end
end

-- Quick Settings Data Structure
local quickSettings = {
    {
        category = "Basic Setup",
        description = "Initialize bot configuration",
        commands = {
            {
                name = "Clear Target & Reset",
                tooltip = "Clears target and resets all bots to balanced stance (2) and default settings",
                actions = {
                    "/target clear",
                    "/say ^stance 2 spawned",
                    "/say ^defaultsettings all spawned"
                }
            }
        }
    },
    {
        category = "Tank Setup",
        description = "Configure tank stances and positioning",
        commands = {
            {
                name = "Setup Tank Roles",
                tooltip = "Warriors to balanced stance (no auto-taunt), Shadowknights to aggressive (auto-taunt for main tanking)",
                actions = {
                    "/say ^stance 2 byclass 1", -- Warriors balanced
                    "/say ^stance 5 byclass 5"  -- Shadowknights aggressive
                }
            }
        }
    },
    {
        category = "Melee DPS Positioning",
        description = "Position melee DPS classes behind mobs",
        commands = {
            {
                name = "Behind Mob Setup",
                tooltip = "Sets Monks, Rogues, Beastlords, and Berserkers to position behind mobs for backstab/positioning bonuses",
                actions = {
                    "/say ^behindmob 1 byclass 7",  -- Monk
                    "/say ^behindmob 1 byclass 9",  -- Rogue
                    "/say ^behindmob 1 byclass 15", -- Beastlord
                    "/say ^behindmob 1 byclass 16"  -- Berserker
                }
            }
        }
    },
    {
        category = "Ranged Setup",
        description = "Configure ranged distances and enable ranged mode",
        commands = {
            {
                name = "Ranged Distances",
                tooltip = "Sets optimal casting/ranged distances: Bards(50), Druids/Shamans(125), Casters(135), Rangers(150)",
                actions = {
                    "/say ^distanceranged 150 byclass 4", -- Ranger
                    "/say ^distanceranged 125 byclass 6", -- Druid
                    "/say ^distanceranged 50 byclass 8",  -- Bard
                    "/say ^distanceranged 125 byclass 10", -- Shaman
                    "/say ^distanceranged 135 byclass 11", -- Necromancer
                    "/say ^distanceranged 135 byclass 12", -- Wizard
                    "/say ^distanceranged 135 byclass 13", -- Magician
                    "/say ^distanceranged 135 byclass 14"  -- Enchanter
                }
            },
            {
                name = "Enable Ranger Ranged",
                tooltip = "Enables ranged combat mode for Rangers to use bows instead of melee",
                actions = {
                    "/say ^bottoggleranged 1 byclass 4" -- Rangers to ranged mode
                }
            }
        }
    },
    {
        category = "Spell Restrictions",
        description = "Control which classes can use specific spell types",
        commands = {
            {
                name = "Nuke Restrictions",
                tooltip = "Only allows Druids, Shamans, Necromancers, Wizards, Magicians, and Enchanters to nuke",
                actions = {
                    "/say ^spellholds nukes 1 spawned",
                    "/say ^spellholds nukes 0 byclass 6",  -- Druid
                    "/say ^spellholds nukes 0 byclass 10", -- Shaman
                    "/say ^spellholds nukes 0 byclass 11", -- Necromancer
                    "/say ^spellholds nukes 0 byclass 12", -- Wizard
                    "/say ^spellholds nukes 0 byclass 13", -- Magician
                    "/say ^spellholds nukes 0 byclass 14"  -- Enchanter
                }
            },
            {
                name = "Healing Restrictions",
                tooltip = "Only allows Druids and Shamans to cast regular heals",
                actions = {
                    "/say ^spellholds regularheals 1 spawned",
                    "/say ^spellholds regularheals 0 byclass 6",  -- Druid
                    "/say ^spellholds regularheals 0 byclass 10"  -- Shaman
                }
            },
            {
                name = "DoT Restrictions",
                tooltip = "Only allows Druids, Bards, Shamans, Necromancers, and Enchanters to cast DoTs",
                actions = {
                    "/say ^spellholds dots 1 spawned",
                    "/say ^spellholds dots 0 byclass 6",  -- Druid
                    "/say ^spellholds dots 0 byclass 8",  -- Bard
                    "/say ^spellholds dots 0 byclass 10", -- Shaman
                    "/say ^spellholds dots 0 byclass 11", -- Necromancer
                    "/say ^spellholds dots 0 byclass 14"  -- Enchanter
                }
            },
            {
                name = "Slow/Debuff Setup",
                tooltip = "Shamans and Enchanters for slows, specific classes for debuffs, disable roots/pets",
                actions = {
                    "/say ^spellholds slows 1 spawned",
                    "/say ^spellholds slows 0 byclass 10", -- Shaman
                    "/say ^spellholds slows 0 byclass 14", -- Enchanter
                    "/say ^spellholds debuffs 1 spawned",
                    "/say ^spellholds debuffs 0 byclass 6",  -- Druid
                    "/say ^spellholds debuffs 0 byclass 8",  -- Bard
                    "/say ^spellholds debuffs 0 byclass 10", -- Shaman
                    "/say ^spellholds debuffs 0 byclass 11", -- Necromancer
                    "/say ^spellholds debuffs 0 byclass 13", -- Magician
                    "/say ^spellholds debuffs 0 byclass 14", -- Enchanter
                    "/say ^spellholds roots 1 spawned", -- Disable roots for everyone
                    "/say ^spellholds pets 1 byclass 5" -- Disable SK pets
                }
            }
        }
    },
    {
        category = "Healing Setup",
        description = "Configure healing priorities and thresholds",
        commands = {
            {
                name = "Tank Healing Priority",
                tooltip = "Sets up complete heals for tanks (Warriors, Paladins, SKs) at 85% health with 3-second chain delays",
                actions = {
                    "/say ^spellholds completeheals 1 spawned",
                    "/say ^spellholds completeheals 0 byclass 1", -- Warrior
                    "/say ^spellholds completeheals 0 byclass 3", -- Paladin
                    "/say ^spellholds completeheals 0 byclass 5", -- Shadowknight
                    "/say ^spellmaxthresholds completeheals 85 byclass 1",
                    "/say ^spellmaxthresholds completeheals 85 byclass 3",
                    "/say ^spellmaxthresholds completeheals 85 byclass 5",
                    "/say ^spelldelays completeheals 3000 byclass 1",
                    "/say ^spelldelays completeheals 3000 byclass 3",
                    "/say ^spelldelays completeheals 3000 byclass 5"
                }
            },
            {
                name = "Fast Heal Thresholds",
                tooltip = "Everyone gets fast heals at 40%, tanks get them at 65%. Very fast heals: everyone 25%, tanks 40%",
                actions = {
                    "/say ^spellmaxthresholds fastheals 40 spawned",
                    "/say ^spellmaxthresholds fastheals 65 byclass 1", -- Warriors
                    "/say ^spellmaxthresholds fastheals 65 byclass 3", -- Paladins
                    "/say ^spellmaxthresholds fastheals 65 byclass 5", -- Shadowknights
                    "/say ^spellmaxthresholds veryfastheals 25 spawned",
                    "/say ^spellmaxthresholds veryfastheals 40 byclass 1",
                    "/say ^spellmaxthresholds veryfastheals 40 byclass 3",
                    "/say ^spellmaxthresholds veryfastheals 40 byclass 5"
                }
            },
            {
                name = "HoT Heal Setup",
                tooltip = "Only tanks receive HoT heals, starting at 95% health. Disables group heals for everyone.",
                actions = {
                    "/say ^spellholds hotheals 1 spawned",
                    "/say ^spellholds hotheals 0 byclass 1", -- Warrior
                    "/say ^spellholds hotheals 0 byclass 3", -- Paladin
                    "/say ^spellholds hotheals 0 byclass 5", -- Shadowknight
                    "/say ^spellmaxthresholds hotheals 95 byclass 1",
                    "/say ^spellmaxthresholds hotheals 95 byclass 3",
                    "/say ^spellmaxthresholds hotheals 95 byclass 5",
                    "/say ^spellholds groupheals 1 spawned",
                    "/say ^spellholds groupcompleteheals 1 spawned",
                    "/say ^spellholds grouphotheals 1 spawned"
                }
            }
        }
    },
    {
        category = "Illusion & Misc",
        description = "Miscellaneous bot settings",
        commands = {
            {
                name = "Block Illusions",
                tooltip = "Prevents bots from being affected by illusion spells",
                actions = {
                    "/say ^illusionblock 1 spawned"
                }
            },
            {
                name = "Disable Pet Healing",
                tooltip = "Disables all pet healing, cures, and buff spells to reduce unnecessary casting",
                actions = {
                    "/say ^spellholds petregularheals 1 spawned",
                    "/say ^spellholds pethotheals 1 spawned",
                    "/say ^spellholds petcompleteheals 1 spawned",
                    "/say ^spellholds petcures 1 spawned",
                    "/say ^spellholds petdamageshields 1 spawned",
                    "/say ^spellholds petresistbuffs 1 spawned"
                }
            }
        }
    }
}

local function _executeQuickCommand(commandData)
    for _, action in ipairs(commandData.actions) do
        _enqueue(function()
            mq.delay(50) -- Small delay between commands
            mq.cmd(action)
        end)
    end
end

function M.toggle()
    M.show = not M.show
    if M.show then
        _registerStanceEvent()
        _registerSpellEvents()
        -- Initial stance refresh when window opens (only if we have no stance data)
        if M._activeTab == 1 and next(M._botStances) == nil then
            _refreshBotStances()
        end
    else
        _unregisterStanceEvent()
        _unregisterSpellEvents()
    end
end

-- Cleanup function (can be called when module unloads)
function M.cleanup()
    _unregisterStanceEvent()
    M._botStances = {}
    M._individualBotWindows = {}
end

function M.draw()
    if not M.show then return end
    
    -- Process any pending MQ2 events (this processes our stance events)
    mq.doevents()

    -- Apply global theming for the entire window
    ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 6)
    ImGui.PushStyleVar(ImGuiStyleVar.PopupRounding, 6)
    ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarRounding, 4)
    ImGui.PushStyleVar(ImGuiStyleVar.GrabRounding, 4)
    ImGui.PushStyleVar(ImGuiStyleVar.TabRounding, 4)
    
    ImGui.PushStyleColor(ImGuiCol.WindowBg, 0.09, 0.09, 0.11, 0.95)
    ImGui.PushStyleColor(ImGuiCol.PopupBg, 0.15, 0.15, 0.20, 0.98)
    ImGui.PushStyleColor(ImGuiCol.FrameBg, 0.2, 0.2, 0.25, 0.9)
    ImGui.PushStyleColor(ImGuiCol.FrameBgHovered, 0.25, 0.25, 0.3, 1.0)
    ImGui.PushStyleColor(ImGuiCol.FrameBgActive, 0.3, 0.3, 0.35, 1.0)
    ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.4, 0.6, 0.8)
    ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.25, 0.45, 0.65, 0.9)
    ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.3, 0.5, 0.7, 1.0)
    ImGui.PushStyleColor(ImGuiCol.Header, 0.2, 0.4, 0.6, 0.8)
    ImGui.PushStyleColor(ImGuiCol.HeaderHovered, 0.25, 0.45, 0.65, 0.9)
    ImGui.PushStyleColor(ImGuiCol.HeaderActive, 0.3, 0.5, 0.7, 1.0)
    ImGui.PushStyleColor(ImGuiCol.Tab, 0.18, 0.18, 0.22, 0.8)
    ImGui.PushStyleColor(ImGuiCol.TabHovered, 0.25, 0.45, 0.65, 0.9)
    ImGui.PushStyleColor(ImGuiCol.TabActive, 0.2, 0.4, 0.6, 1.0)

    -- Resizable window (no auto-resize). Set sensible first-use size/constraints.
    ImGui.SetNextWindowSize(ImVec2(680, 600), ImGuiCond.FirstUseEver)
    ImGui.SetNextWindowSizeConstraints(ImVec2(200, 300), ImVec2(1600, 1200))
    local isOpen, _ = ImGui.Begin('Bot Controls##EmuBotToggles', true)
    if not isOpen then 
        -- Respect the window close (X)
        M.show = false
        ImGui.End()
        ImGui.PopStyleColor(14)
        ImGui.PopStyleVar(6)
        return 
    end

    -- Create tabs
    if ImGui.BeginTabBar('BotControlTabs') then
        -- Bot Controls Tab
        if ImGui.BeginTabItem('Bot Controls') then
            M._activeTab = 1
            M._drawBotControlsTab()
            ImGui.EndTabItem()
        end
        
        -- Quick Settings Tab
        if ImGui.BeginTabItem('Quick Commands') then
            M._activeTab = 2
            M._drawQuickSettingsTab()
            ImGui.EndTabItem()
        end

        -- Batch Commands Tab
        if ImGui.BeginTabItem('Batch Commands') then
            M._activeTab = 3
            M._drawBatchCommandsTab()
            ImGui.EndTabItem()
        end

        
        ImGui.EndTabBar()
    end

    -- Handle spell prompt popup (shared between tabs)
    if M._spellPrompt and M._spellPrompt.open then
        ImGui.OpenPopup('Announce Casts##spell_prompt')
        M._spellPrompt.open = false
    end
    if ImGui.BeginPopupModal('Announce Casts##spell_prompt', nil, ImGuiWindowFlags.AlwaysAutoResize) then
        ImGui.Text('Enter spell type shortname (e.g., nuke, heal, debuff):')
        local cur = M._spellPrompt and M._spellPrompt.typeText or ''
        local newTxt = ImGui.InputText('##spelltype_prompt', cur)
        if newTxt ~= nil and M._spellPrompt then M._spellPrompt.typeText = newTxt end

        ImGui.Text('Mode:')
        local smodes = { 'enable', 'disable', 'current' }
        local sel = 3
        if M._spellPrompt and M._spellPrompt.mode == 'enable' then sel = 1
        elseif M._spellPrompt and M._spellPrompt.mode == 'disable' then sel = 2 end
        local newSel, changed = ImGui.Combo('##spellmode', sel, smodes)
        if changed and newSel ~= nil then M._spellPrompt.mode = smodes[newSel] end

        if ImGui.Button('OK', 100, 0) then
            local b = M._spellPrompt.bot
            local t = M._spellPrompt.typeText or ''
            local m = M._spellPrompt.mode or 'current'
            if b and t ~= '' then
                if m == 'enable' then _runForBot(b, string.format('^spellannouncecasts %s 1 target', t))
                elseif m == 'disable' then _runForBot(b, string.format('^spellannouncecasts %s 0 target', t))
                else _runForBot(b, string.format('^spellannouncecasts %s current target', t)) end
            end
            ImGui.CloseCurrentPopup()
        end
        ImGui.SameLine()
        if ImGui.Button('Cancel', 100, 0) then ImGui.CloseCurrentPopup() end
        ImGui.EndPopup()
    end

    -- Add-spell floating window (non-modal)
    if M._addSpellPrompt and M._addSpellPrompt.show then
        ImGui.SetNextWindowSizeConstraints(ImVec2(320, 0), ImVec2(480, 600))
        local open = ImGui.Begin('Add Learned Spell##add_spell_prompt', true, ImGuiWindowFlags.AlwaysAutoResize)
        if not open then
            M._addSpellPrompt.show = false
        else
            local p = M._addSpellPrompt or {}
            ImGui.Text(string.format('Add "%s" (ID %s) to allowed list', tostring(p.name or ''), tostring(p.id or '')))
            ImGui.Separator()
            ImGui.Text('Priority:')
            local priStr = tostring(p.priority or '0')
            local priNew = ImGui.InputText('##addspell_pri', priStr)
            if priNew ~= nil then p.priority = tonumber(priNew) or 0 end
            ImGui.Text('Min HP (-1..99):')
            local minStr = tostring(p.min_hp or '-1')
            local minNew = ImGui.InputText('##addspell_min', minStr)
            if minNew ~= nil then p.min_hp = tonumber(minNew) or -1 end
            ImGui.Text('Max HP (-1..100):')
            local maxStr = tostring(p.max_hp or '100')
            local maxNew = ImGui.InputText('##addspell_max', maxStr)
            if maxNew ~= nil then p.max_hp = tonumber(maxNew) or 100 end

            if ImGui.Button('Add', 100, 0) then
                local id = tonumber(p.id or 0) or 0
                local pri = tonumber(p.priority or 0) or 0
                local minv = tonumber(p.min_hp or -1) or -1
                local maxv = tonumber(p.max_hp or 100) or 100
                if p.bot and id > 0 then
                    _runForBot(p.bot, string.format('^spellsettingsadd %d %d %d %d target', id, pri, minv, maxv))
                end
                M._addSpellPrompt.show = false
            end
            ImGui.SameLine()
            if ImGui.Button('Cancel', 100, 0) then M._addSpellPrompt.show = false end
            M._addSpellPrompt = p
        end
        ImGui.End()
    end

    -- No bottom close button; use the window X
    ImGui.End()
    
    -- Pop all global theming
    ImGui.PopStyleColor(14) -- Pop all the colors we pushed (added 3 header colors)
    ImGui.PopStyleVar(6)    -- Pop all the vars we pushed
    
    -- Draw individual bot windows
    M._drawIndividualBotWindows()
end

function M._drawBotControlsTab()
    local names = _getSpawnedBots()

    ImGui.TextColored(0.95, 0.85, 0.2, 1.0, string.format('Spawned (%d)', #names))
    
    -- Manual refresh button (for initial load or troubleshooting)
    ImGui.SameLine()
    if ImGui.SmallButton('Refresh Stances##refresh_stances') then
        _refreshBotStances()
    end
    if ImGui.IsItemHovered() then
        ImGui.SetTooltip('Manually query all spawned bots for their current stance.\nStances update automatically when changed via dropdown or Mode menu.')
    end
    
    -- Toggle between names and classes
    ImGui.SameLine()
    local toggleText = M._showClassNames and "Show Names" or "Show Classes"
    if ImGui.SmallButton(toggleText .. '##toggle_display') then
        M._showClassNames = not M._showClassNames
    end
    if ImGui.IsItemHovered() then
        local tooltip = M._showClassNames and "Click to show bot names instead of classes" or "Click to show bot classes instead of names"
        ImGui.SetTooltip(tooltip)
    end
    
    ImGui.Separator()

    local tableFlags = bit32.bor(
        ImGuiTableFlags.Borders,
        ImGuiTableFlags.RowBg,
        ImGuiTableFlags.Resizable,
        ImGuiTableFlags.ScrollY
    )

    if ImGui.BeginTable('BotControlsTable', 2, tableFlags) then
        local columnHeader = M._showClassNames and 'Class' or 'Bot'
        local columnWidth = M._showClassNames and 80 or 120
        ImGui.TableSetupColumn(columnHeader, ImGuiTableColumnFlags.WidthFixed, columnWidth)
        ImGui.TableSetupColumn('Stance', ImGuiTableColumnFlags.WidthFixed, 120)
        ImGui.TableHeadersRow()

        for i, botName in ipairs(names) do
            ImGui.TableNextRow()
            ImGui.TableNextColumn()
            local displayName = M._showClassNames and _getBotClass(botName) or botName
            local label = string.format('%s##botrow_%d', displayName, i)
            if ImGui.Selectable(label, false) then _targetBotByName(botName) end
            
            -- Context menu for the bot name column only
            if ImGui.BeginPopupContextItem('ctx_' .. botName) then
                if ImGui.BeginMenu('Taunt') then
                    if ImGui.MenuItem('On') then _runForBot(botName, '^taunt on target') end
                    if ImGui.MenuItem('Off') then _runForBot(botName, '^taunt off target') end
                    if ImGui.MenuItem('Pet On') then _runForBot(botName, '^taunt on pet target') end
                    if ImGui.MenuItem('Pet Off') then _runForBot(botName, '^taunt off pet target') end
                    ImGui.EndMenu()
                end

                if ImGui.BeginMenu('Behind Mob') then
                    if ImGui.MenuItem('Enable') then _runForBot(botName, '^behindmob 1 target') end
                    if ImGui.MenuItem('Disable') then _runForBot(botName, '^behindmob 0 target') end
                    if ImGui.MenuItem('Current') then _runForBot(botName, '^behindmob current target') end
                    ImGui.EndMenu()
                end

                if ImGui.BeginMenu('Max Melee Range') then
                    if ImGui.MenuItem('Enable') then _runForBot(botName, '^maxmeleerange 1 target') end
                    if ImGui.MenuItem('Disable') then _runForBot(botName, '^maxmeleerange 0 target') end
                    if ImGui.MenuItem('Current') then _runForBot(botName, '^maxmeleerange current target') end
                    ImGui.EndMenu()
                end

                if ImGui.BeginMenu('Hold') then
                    if ImGui.MenuItem('Set') then _runForBot(botName, '^hold target') end
                    if ImGui.MenuItem('Clear') then _runForBot(botName, '^hold clear target') end
                    ImGui.EndMenu()
                end

                if ImGui.BeginMenu('Ranged Mode') then
                    if ImGui.MenuItem('Enable') then _runForBot(botName, '^bottoggleranged 1 target') end
                    if ImGui.MenuItem('Disable') then _runForBot(botName, '^bottoggleranged 0 target') end
                    if ImGui.MenuItem('Current') then _runForBot(botName, '^bottoggleranged current target') end
                    ImGui.EndMenu()
                end

                if ImGui.BeginMenu('Follow Distance') then
                    if ImGui.MenuItem('Set 10') then _runForBot(botName, '^botfollowdistance set 10 target') end
                    if ImGui.MenuItem('Set 25') then _runForBot(botName, '^botfollowdistance set 25 target') end
                    if ImGui.MenuItem('Set 50') then _runForBot(botName, '^botfollowdistance set 50 target') end
                    if ImGui.MenuItem('Current') then _runForBot(botName, '^botfollowdistance current target') end
                    if ImGui.MenuItem('Reset') then _runForBot(botName, '^botfollowdistance reset target') end
                    ImGui.EndMenu()
                end

            if ImGui.BeginMenu('Mode') then
                if ImGui.MenuItem('Current') then _runForBot(botName, '^stance current target') end
                ImGui.Separator()
                if ImGui.MenuItem('Passive (1)') then 
                    _runForBot(botName, '^stance 1 target')
                    _setBotStance(botName, 1)
                end
                if ImGui.MenuItem('Balanced (2)') then 
                    _runForBot(botName, '^stance 2 target')
                    _setBotStance(botName, 2)
                end
                if ImGui.MenuItem('Efficient (3)') then 
                    _runForBot(botName, '^stance 3 target')
                    _setBotStance(botName, 3)
                end
                if ImGui.MenuItem('Reactive (4)') then 
                    _runForBot(botName, '^stance 4 target')
                    _setBotStance(botName, 4)
                end
                if ImGui.MenuItem('Aggressive (5)') then 
                    _runForBot(botName, '^stance 5 target')
                    _setBotStance(botName, 5)
                end
                if ImGui.MenuItem('Assist (6)') then 
                    _runForBot(botName, '^stance 6 target')
                    _setBotStance(botName, 6)
                end
                if ImGui.MenuItem('Burn (7)') then 
                    _runForBot(botName, '^stance 7 target')
                    _setBotStance(botName, 7)
                end
                if ImGui.MenuItem('Efficient Alt (8)') then 
                    _runForBot(botName, '^stance 8 target')
                    _setBotStance(botName, 8)
                end
                if ImGui.MenuItem('AE Burn (9)') then 
                    _runForBot(botName, '^stance 9 target')
                    _setBotStance(botName, 9)
                end
                ImGui.EndMenu()
            end

            ImGui.Separator()
            if ImGui.MenuItem('Individual Bot Window...') then
                M._individualBotWindows[botName] = {
                    show = true,
                    botName = botName,
                    activeTab = 1,
                    customDistance = "25", -- Default custom distance
                    spellCategoryFilter = 'All'
                }
            end

                ImGui.EndPopup()
            end
            
            -- Stance column - Dropdown for stance selection
            ImGui.TableNextColumn()
            local currentStanceIndex = _getStanceDropdownIndex(botName)
            local dropdownId = string.format('##stance_%s_%d', botName, i)
            
            -- Set dropdown width to 80 units
            ImGui.PushItemWidth(130)
            local newIndex, changed = ImGui.Combo(dropdownId, currentStanceIndex, stanceDropdownOptions)
            ImGui.PopItemWidth()
            
            if changed and newIndex ~= currentStanceIndex then
                -- User changed stance via dropdown
                _runForBot(botName, string.format('^stance %d target', newIndex))
                _setBotStance(botName, newIndex)
            end
        end

        ImGui.EndTable()
    end
end

function M._drawQuickSettingsTab()
    ImGui.TextColored(0.95, 0.85, 0.2, 1.0, 'Quick Settings')
    ImGui.TextColored(0.7, 0.7, 0.7, 1.0, 'One-click configuration presets based on your macro settings')
    ImGui.Separator()

    -- Create a scrolling region for the settings
    if ImGui.BeginChild('QuickSettingsScroll', 0, -30, true) then
        for categoryIndex, category in ipairs(quickSettings) do
            -- Category header (styled by global theming)
            local expanded = ImGui.CollapsingHeader(string.format('%s##cat_%d', category.category, categoryIndex), ImGuiTreeNodeFlags.DefaultOpen)
            
            if expanded then
                ImGui.TextWrapped(category.description)
                ImGui.Spacing()
                
                -- Commands in this category (layout: 3 per row)
                local colCount = 0
                for cmdIndex, command in ipairs(category.commands) do
                    local buttonId = string.format('%s##cmd_%d_%d', command.name, categoryIndex, cmdIndex)
                    if ImGui.Button(buttonId, 0, 0) then
                        _executeQuickCommand(command)
                    end
                    -- Show tooltip on hover
                    if ImGui.IsItemHovered() then
                        ImGui.SetTooltip(command.tooltip)
                    end
                    colCount = colCount + 1
                    if (colCount % 3) ~= 0 then
                        ImGui.SameLine()
                    end
                end
                
                ImGui.Spacing()
                ImGui.Separator()
                ImGui.Spacing()
            end
        end
        
        ImGui.EndChild()
    end
    
    ImGui.Separator()
    ImGui.TextColored(0.6, 0.6, 0.6, 1.0, 'Hover over buttons for detailed descriptions')
end

function M._drawIndividualBotWindows()
    -- Draw all open individual bot windows
    for botName, windowState in pairs(M._individualBotWindows) do
        if windowState.show then
            M._drawIndividualBotWindow(botName, windowState)
        end
    end
    
    -- Clean up closed windows
    for botName, windowState in pairs(M._individualBotWindows) do
        if not windowState.show then
            M._individualBotWindows[botName] = nil
        end
    end
end

function M._drawIndividualBotWindow(botName, windowState)
    -- Apply the same theming as main window
    ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 6)
    ImGui.PushStyleVar(ImGuiStyleVar.PopupRounding, 6)
    ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarRounding, 4)
    ImGui.PushStyleVar(ImGuiStyleVar.GrabRounding, 4)
    ImGui.PushStyleVar(ImGuiStyleVar.TabRounding, 4)
    
    ImGui.PushStyleColor(ImGuiCol.WindowBg, 0.09, 0.09, 0.11, 0.95)
    ImGui.PushStyleColor(ImGuiCol.PopupBg, 0.15, 0.15, 0.20, 0.98)
    ImGui.PushStyleColor(ImGuiCol.FrameBg, 0.2, 0.2, 0.25, 0.9)
    ImGui.PushStyleColor(ImGuiCol.FrameBgHovered, 0.25, 0.25, 0.3, 1.0)
    ImGui.PushStyleColor(ImGuiCol.FrameBgActive, 0.3, 0.3, 0.35, 1.0)
    ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.4, 0.6, 0.8)
    ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.25, 0.45, 0.65, 0.9)
    ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.3, 0.5, 0.7, 1.0)
    ImGui.PushStyleColor(ImGuiCol.Header, 0.2, 0.4, 0.6, 0.8)
    ImGui.PushStyleColor(ImGuiCol.HeaderHovered, 0.25, 0.45, 0.65, 0.9)
    ImGui.PushStyleColor(ImGuiCol.HeaderActive, 0.3, 0.5, 0.7, 1.0)
    ImGui.PushStyleColor(ImGuiCol.Tab, 0.18, 0.18, 0.22, 0.8)
    ImGui.PushStyleColor(ImGuiCol.TabHovered, 0.25, 0.45, 0.65, 0.9)
    ImGui.PushStyleColor(ImGuiCol.TabActive, 0.2, 0.4, 0.6, 1.0)
    
    local windowTitle = string.format('%s - Bot Controls###IndividualBot_%s', botName, botName)
    ImGui.SetNextWindowSize(ImVec2(450, 500), ImGuiCond.FirstUseEver)
    ImGui.SetNextWindowSizeConstraints(ImVec2(350, 400), ImVec2(800, 800))
    
    local isOpen = ImGui.Begin(windowTitle, true, ImGuiWindowFlags.MenuBar)
    if not isOpen then
        windowState.show = false
        ImGui.End()
        ImGui.PopStyleColor(14)
        ImGui.PopStyleVar(6)
        return
    end
    
    -- Menu bar with bot info
    if ImGui.BeginMenuBar() then
        ImGui.TextColored(0.95, 0.85, 0.2, 1.0, string.format('Bot: %s', botName))
        if ImGui.SmallButton('Close') then
            windowState.show = false
        end
        ImGui.EndMenuBar()
    end
    ImGui.Separator()
    
    -- Tab bar for different control sections
    if ImGui.BeginTabBar('IndividualBotTabs') then
        -- General tab
        if ImGui.BeginTabItem('General') then
            M._drawIndividualBotGeneralTab(botName, windowState)
            ImGui.EndTabItem()
        end
        
        -- Stance & Behavior tab
        if ImGui.BeginTabItem('Stance & Behavior') then
            M._drawIndividualBotStanceTab(botName, windowState)
            ImGui.EndTabItem()
        end
        
        -- Spells & Abilities tab
        if ImGui.BeginTabItem('Spells & Abilities') then
            M._drawIndividualBotSpellsTab(botName, windowState)
            ImGui.EndTabItem()
        end
        
        -- Settings tab
        if ImGui.BeginTabItem('Settings') then
            M._drawIndividualBotSettingsTab(botName, windowState)
            ImGui.EndTabItem()
        end
        
        ImGui.EndTabBar()
    end
    
    ImGui.End()
    
    -- Pop all theming
    ImGui.PopStyleColor(14)
    ImGui.PopStyleVar(6)
end

function M._drawIndividualBotGeneralTab(botName, windowState)
    ImGui.TextColored(0.95, 0.85, 0.2, 1.0, 'General Controls')
    ImGui.Separator()
    
    -- Basic commands section
    if ImGui.CollapsingHeader('Basic Commands', ImGuiTreeNodeFlags.DefaultOpen) then
        _row3_reset()
        _button3('Target Bot', 120, 'Target this bot so you can interact with them directly', function() _targetBotByName(botName) end)
        _button3('Camp Bot', 120, 'Make the bot camp (disappear from the world but stay logged in)', function() _runForBot(botName, '^camp target') end)
        _button3('Follow Me', 120, 'Bot will start following you at their configured follow distance', function() _runForBot(botName, '^follow reset target') end)
        _button3('Come to Me', 120, 'Bot will immediately run to your exact location (ignores follow distance)', function() _runForBot(botName, '^come target') end)
        _button3('Hold Position', 120, 'Bot will stop moving and stay at their current location', function() _runForBot(botName, '^hold target') end)
        _button3('Clear Hold', 120, 'Remove hold status, bot will resume normal following behavior', function() _runForBot(botName, '^hold clear target') end)
    end
    
    -- Status section
    if ImGui.CollapsingHeader('Status', ImGuiTreeNodeFlags.DefaultOpen) then
        _row3_reset()
        _button3('Health Report', 120, 'Bot will report their current health, mana, and endurance percentages', function() _runForBot(botName, '^report target') end)
        _button3('Inventory Report', 120, 'Bot will list all equipped items (slot by slot inventory)', function() _runForBot(botName, '^invlist target') end)
        _button3('Stats Report', 120, 'Bot will report their current stats (STR, STA, DEX, AGI, INT, WIS, CHA)', function() _runForBot(botName, '^stats target') end)
        _button3('Spell List', 120, 'Bot will list all spells they currently have memorized', function() _runForBot(botName, '^spells target') end)
    end
end

function M._drawIndividualBotStanceTab(botName, windowState)
    ImGui.TextColored(0.95, 0.85, 0.2, 1.0, 'Stance & Behavior Controls')
    ImGui.Separator()
    
    -- Stance selection
    if ImGui.CollapsingHeader('Combat Stance', ImGuiTreeNodeFlags.DefaultOpen) then
        ImGui.Text('Current Stance:')
        ImGui.SameLine()
        local currentStanceIndex = _getStanceDropdownIndex(botName)
        local newIndex, changed = ImGui.Combo('##individual_stance', currentStanceIndex, stanceDropdownOptions)
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Select combat stance:\nPassive: No combat unless attacked\nBalanced: Standard behavior\nEfficient: Conserves resources\nReactive: Quick response\nAggressive: High damage/aggro\nAssist: Focus on group support\nBurn: Use powerful abilities\nEfficient Alt: Alternative conservation\nAE Burn: Area damage focused')
        end
        if changed and newIndex ~= currentStanceIndex then
            _runForBot(botName, string.format('^stance %d target', newIndex))
            _setBotStance(botName, newIndex)
        end
        
        if ImGui.Button('Query Current Stance', 200, 0) then
            _runForBot(botName, '^stance current target')
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Ask the bot to report their current combat stance setting')
        end
    end
    
    -- Position controls
    if ImGui.CollapsingHeader('Positioning', ImGuiTreeNodeFlags.DefaultOpen) then
        _row3_reset()
        _button3('Behind Mob: ON', 120, 'Bot will try to position behind the target for backstab bonuses (good for rogues/monks)', function() _runForBot(botName, '^behindmob 1 target') end)
        _button3('Behind Mob: OFF', 120, 'Bot will attack from any position (standard melee positioning)', function() _runForBot(botName, '^behindmob 0 target') end)
        _button3('Max Melee Range: ON', 120, 'Bot will stay at maximum melee range (good for avoiding AE attacks)', function() _runForBot(botName, '^maxmeleerange 1 target') end)
        _button3('Max Melee Range: OFF', 120, 'Bot will fight at normal close melee range', function() _runForBot(botName, '^maxmeleerange 0 target') end)
        _button3('Ranged Mode: ON', 120, 'Bot will use ranged weapons (bows/throwing) instead of melee weapons', function() _runForBot(botName, '^bottoggleranged 1 target') end)
        _button3('Ranged Mode: OFF', 120, 'Bot will use melee weapons for combat (normal mode)', function() _runForBot(botName, '^bottoggleranged 0 target') end)
    end
    
    -- Taunt controls
    if ImGui.CollapsingHeader('Taunt Settings') then
        _row3_reset()
        _button3('Taunt: ON', 120, 'Bot will use taunt abilities to maintain aggro (good for tanks)', function() _runForBot(botName, '^taunt on target') end)
        _button3('Taunt: OFF', 120, 'Bot will not use taunt abilities (good for DPS to avoid stealing aggro)', function() _runForBot(botName, '^taunt off target') end)
        _button3('Pet Taunt: ON', 120, 'Bot\'s pet will use taunt abilities (pet will try to tank)', function() _runForBot(botName, '^taunt on pet target') end)
        _button3('Pet Taunt: OFF', 120, 'Bot\'s pet will not use taunt abilities (pet will not try to tank)', function() _runForBot(botName, '^taunt off pet target') end)
    end
end

function M._drawIndividualBotSpellsTab(botName, windowState)
    ImGui.TextColored(0.95, 0.85, 0.2, 1.0, 'Spell & Ability Controls')
    ImGui.Separator()
    
    -- Spell casting controls
    if ImGui.CollapsingHeader('Spell Controls', ImGuiTreeNodeFlags.DefaultOpen) then
        _row3_reset()
        _button3('Stop Casting', 150, 'Interrupt the bot\'s current spell casting (emergency stop)', function() _runForBot(botName, '^interrupt target') end)
        _button3('Mem Spells', 150, 'Bot will memorize their default spell set (replaces current gems)', function() _runForBot(botName, '^memspells target') end)
        _button3('Show Spell Gems', 150, 'Bot will report what spells are currently memorized in each gem slot', function() _runForBot(botName, '^spellgems target') end)
    end
    
    -- Buff controls
    if ImGui.CollapsingHeader('Buff Management') then
        _row3_reset()
        _button3('Cast Buffs', 120, 'Bot will cast all available buff spells on group members', function() _runForBot(botName, '^prebuff target') end)
        _button3('Stop Buffing', 120, 'Bot will stop casting buff spells (emergency stop for buff routines)', function() _runForBot(botName, '^stopbuff target') end)
        _button3('Remove Buffs', 120, 'Bot will remove/cancel their buff spells from all group members', function() _runForBot(botName, '^removebuffs target') end)
        _button3('Buff Report', 120, 'Bot will report what buff spells they currently have active', function() _runForBot(botName, '^buffs target') end)
    end
    
    -- Announce settings
    if ImGui.CollapsingHeader('Announce Settings') then
        ImGui.Text('Configure spell announce:')
        _row3_reset()
        _button3('Open Spell Announce...', 200, 'Opens dialog to configure which spell types this bot announces when casting', function()
            M._spellPrompt = { open = true, bot = botName, typeText = '', mode = 'current' }
        end)
        ImGui.NewLine()
        ImGui.TextWrapped('Use this to configure which spell types this bot should announce when casting.')
    end

    -- Learned spells and allow-list management
    if ImGui.CollapsingHeader('Learned Spells (from ^spells)', ImGuiTreeNodeFlags.DefaultOpen) then
        local store = _ensureBotSpellStore(botName)
        if ImGui.Button('Refresh Learned Spells', 200, 0) then
            _requestBotSpells(botName)
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Queries the bot and parses ^spells output via MQ event')
        end

        ImGui.SameLine()
        if ImGui.Button('Enforce Allowed: ON', 150, 0) then
            _runForBot(botName, '^enforcespellsettings 1 target')
        end
        if ImGui.IsItemHovered() then ImGui.SetTooltip('Only cast spells on the allowed list') end
        ImGui.SameLine()
        if ImGui.Button('Enforce Allowed: OFF', 150, 0) then
            _runForBot(botName, '^enforcespellsettings 0 target')
        end
        if ImGui.IsItemHovered() then ImGui.SetTooltip('Allow bot to use all spells normally') end

        ImGui.Separator()

        if store.loading and (#store.entries == 0) then
            ImGui.TextColored(0.7, 0.7, 0.7, 1.0, 'Waiting for spell list...')
        elseif (not store.loading) and (#store.entries == 0) then
            ImGui.TextColored(0.7, 0.7, 0.7, 1.0, 'No learnable spells returned. Check enforcement or min level filter.')
        end

        if #store.entries > 0 then
            -- Sort by index then name for stable display
            table.sort(store.entries, function(a,b)
                if tonumber(a.index or 0) == tonumber(b.index or 0) then
                    return tostring(a.name or ''):lower() < tostring(b.name or ''):lower()
                end
                return tonumber(a.index or 0) < tonumber(b.index or 0)
            end)

            local learnedTableFlags = bit32.bor(
                ImGuiTableFlags.Borders,
                ImGuiTableFlags.RowBg,
                ImGuiTableFlags.Resizable,
                ImGuiTableFlags.ScrollY
            )
            -- Build groups and "All" list
            local groups = {}
            local allEntries = {}
            for _, e in ipairs(store.entries) do
                e.category = e.category or _getSpellCategory(e.id)
                local cat = e.category or 'Unknown'
                groups[cat] = groups[cat] or {}
                table.insert(groups[cat], e)
                table.insert(allEntries, e)
            end
            local function sortEntries(t)
                table.sort(t, function(a,b)
                    if tonumber(a.index or 0) == tonumber(b.index or 0) then
                        return tostring(a.name or ''):lower() < tostring(b.name or ''):lower()
                    end
                    return tonumber(a.index or 0) < tonumber(b.index or 0)
                end)
            end
            for _, list in pairs(groups) do sortEntries(list) end
            sortEntries(allEntries)

            -- Sorted category names
            local catList = {}
            for k,_ in pairs(groups) do table.insert(catList, k) end
            table.sort(catList, function(a,b) return a:lower() < b:lower() end)

            -- Two-pane child region: left categories, right spells
            if ImGui.BeginChild('LearnedSpellsSplit', 0, 320, true) then
                -- Left pane
                if ImGui.BeginChild('LearnedSpellsCategories', 220, 0, true) then
                    -- All category first
                    local allLabel = string.format('All (%d)', #allEntries)
                    windowState.spellCategorySelected = windowState.spellCategorySelected or 'All'
                    local selIsAll = windowState.spellCategorySelected == 'All'
                    if ImGui.Selectable(allLabel, selIsAll) then windowState.spellCategorySelected = 'All' end
                    -- Each real category
                    for _, cat in ipairs(catList) do
                        local label = string.format('%s (%d)', cat, #(groups[cat] or {}))
                        local selected = windowState.spellCategorySelected == cat
                        if ImGui.Selectable(label, selected) then windowState.spellCategorySelected = cat end
                    end
                end
                ImGui.EndChild()

                ImGui.SameLine()

                -- Right pane
                if ImGui.BeginChild('LearnedSpellsList', 0, 0, true) then
                    local selectedCat = windowState.spellCategorySelected or 'All'
                    local list = selectedCat == 'All' and allEntries or (groups[selectedCat] or {})

                    if ImGui.BeginTable('LearnedSpellsListTable', 3, learnedTableFlags) then
                        ImGui.TableSetupColumn('Index', ImGuiTableColumnFlags.WidthFixed, 50)
                        ImGui.TableSetupColumn('Name', ImGuiTableColumnFlags.WidthStretch)
                        ImGui.TableSetupColumn('Actions', ImGuiTableColumnFlags.WidthFixed, 220)
                        ImGui.TableHeadersRow()
                        for i, e in ipairs(list) do
                            ImGui.TableNextRow()
                            ImGui.TableNextColumn(); ImGui.Text(tostring(e.index or ''))
                            ImGui.TableNextColumn(); ImGui.Text(tostring(e.name or ''))
                            ImGui.TableNextColumn()
                            local addId = string.format('Add##add_%s_%d_%s', botName, i, selectedCat)
                    if ImGui.SmallButton(addId) then
                        M._addSpellPrompt = {
                            show = true,
                            bot = botName,
                            id = tonumber(e.id or 0) or 0,
                            name = tostring(e.name or ''),
                            priority = 0,
                            min_hp = -1,
                            max_hp = 100
                        }
                    end
                            if ImGui.IsItemHovered() then ImGui.SetTooltip('Add this spell to the allowed list (choose priority and HP thresholds)') end
                            ImGui.SameLine()
                            local infoId = string.format('Info##info_%s_%d_%s', botName, i, selectedCat)
                            if ImGui.SmallButton(infoId) then
                                _runForBot(botName, string.format('^spellinfo %d target', tonumber(e.id or 0) or 0))
                            end
                            if ImGui.IsItemHovered() then ImGui.SetTooltip('Open spell info window for details') end
                        end
                        ImGui.EndTable()
                    end
                end
                ImGui.EndChild()
            end
            ImGui.EndChild()
        end

        -- Mark loading complete once we have some entries; more lines can still append
        if #store.entries > 0 then store.loading = false end
    end
end

function M._drawIndividualBotSettingsTab(botName, windowState)
    ImGui.TextColored(0.95, 0.85, 0.2, 1.0, 'Bot Settings')
    ImGui.Separator()
    
    -- Display settings
    if ImGui.CollapsingHeader('Display Settings', ImGuiTreeNodeFlags.DefaultOpen) then
        _row3_reset()
        _button3('Show Helm: ON', 120, 'Bot will display their helmet/hat (visible headgear)', function() _runForBot(botName, '^bottogglehelm 1 target') end)
        _button3('Show Helm: OFF', 120, 'Bot will hide their helmet/hat (face visible, stats still apply)', function() _runForBot(botName, '^bottogglehelm 0 target') end)
    end
    
    -- Follow distance
    if ImGui.CollapsingHeader('Follow Distance') then
        -- Quick preset buttons (3 per row)
        _row3_reset()
        _button3('Distance: 10', 100, 'Set follow distance to 10 units (very close following)', function() _runForBot(botName, '^botfollowdistance set 10 target') end)
        _button3('Distance: 25', 100, 'Set follow distance to 25 units (standard close following)', function() _runForBot(botName, '^botfollowdistance set 25 target') end)
        _button3('Distance: 50', 100, 'Set follow distance to 50 units (loose formation following)', function() _runForBot(botName, '^botfollowdistance set 50 target') end)
        
        -- Custom distance input
        ImGui.Separator()
        ImGui.Text('Custom Distance:')
        ImGui.SameLine()
        local newDistance = ImGui.InputText('##custom_distance', windowState.customDistance or "25", 8)
        if newDistance ~= nil then
            windowState.customDistance = newDistance
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Enter a custom follow distance (recommended: 10-100)')
        end
        
        ImGui.SameLine()
        if ImGui.Button('Apply##apply_distance', 60, 0) then
            local distance = tonumber(windowState.customDistance) or 25
            if distance > 0 and distance <= 500 then
                _runForBot(botName, string.format('^botfollowdistance set %d target', distance))
            end
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Apply the custom distance value (must be 1-500)')
        end
        
        -- Management buttons (3 per row)
        ImGui.Separator()
        _row3_reset()
        _button3('Reset Distance', 120, 'Reset follow distance to server/character default', function() _runForBot(botName, '^botfollowdistance reset target') end)
        _button3('Query Distance', 120, 'Ask the bot to report their current follow distance setting', function() _runForBot(botName, '^botfollowdistance current target') end)
    end
    
    -- Combat settings
    if ImGui.CollapsingHeader('Combat Settings') then
        _row3_reset()
        _button3('Sit In Combat: ON', 120, 'Bot will sit during combat to regenerate mana/health faster (risky but efficient)', function() _runForBot(botName, '^sitincombat 1 target') end)
        _button3('Sit In Combat: OFF', 120, 'Bot will stand during combat for safety (standard behavior)', function() _runForBot(botName, '^sitincombat 0 target') end)
        
        ImGui.TextWrapped('When enabled, bot will sit during combat to regenerate mana/health faster.')
    end
    
    -- Advanced settings
    if ImGui.CollapsingHeader('Advanced') then
        _row3_reset()
        _button3('Default Settings', 150, 'Reset all bot settings to server defaults (stance, distances, behaviors, etc.)', function() _runForBot(botName, '^defaultsettings target') end)
        _button3('Save Settings', 150, 'Save current bot configuration to database (preserves settings across sessions)', function() _runForBot(botName, '^save target') end)
        
        ImGui.TextWrapped('Reset bot to default settings or save current configuration.')
    end
end

function M._drawBatchCommandsTab()
    local B = M._batch
    local names = B.includeSpawnedOnly and _getSpawnedBots() or (bot_inventory.getAllBots and bot_inventory.getAllBots() or {})
    table.sort(names, function(a,b) return (a or ''):lower() < (b or ''):lower() end)

    -- Top controls: spawned-only toggle, queue delay, filter, command input
    do
        local newVal, pressed = ImGui.Checkbox('Spawned Only##batch_spawned', B.includeSpawnedOnly)
        if pressed then B.includeSpawnedOnly = newVal and true or false end
    end
    ImGui.SameLine()
    ImGui.Text('Delay (ms):')
    ImGui.SameLine()
    local delayStr = tostring(B.queueDelayMs or 75)
    local delayNew = ImGui.InputText('##batch_delay', delayStr)
    if delayNew ~= nil then B.queueDelayMs = tonumber(delayNew) or B.queueDelayMs end
    ImGui.SameLine()
    ImGui.Text('Filter:')
    ImGui.SameLine()
    local fnew = ImGui.InputText('##batch_filter', B.filterText or '')
    if fnew ~= nil then B.filterText = fnew end

    ImGui.Separator()

    -- Calculate remaining height so the split fills the window
    local winH = ImGui.GetWindowHeight()
    local curY = ImGui.GetCursorPosY()
    local remainingH = winH - curY - 40 -- margin for bottom padding

    if ImGui.BeginChild('BatchSplit', 0, remainingH, true) then
        -- Two panes: Left (groups), Right (bot list + group detail)
        local availW = 600
        do
            local a, b = ImGui.GetContentRegionAvail()
            if type(a) == 'number' and type(b) == 'number' then
                availW = a
            elseif type(a) == 'table' and a.x then
                availW = a.x
            end
        end
        -- Keep left pane compact - just enough for group names and buttons
        local leftW = 200
        if ImGui.BeginChild('BatchLeft', 180, 0, true) then
            ImGui.TextColored(0.95, 0.85, 0.2, 1.0, 'Groups')
            -- List groups (sorted, stable IDs) with delete buttons
            local groupNames = {}
            for name,_ in pairs(B.groups) do table.insert(groupNames, tostring(name)) end
            table.sort(groupNames, function(a,b) return a:lower() < b:lower() end)
            local deletedName = nil
            
            -- Scrollable area for groups list
            local groupsListHeight = math.min(200, (#groupNames * 25) + 30)
            if ImGui.BeginChild('GroupsListScroll', 0, groupsListHeight, true) then
                -- Use a table to properly layout group name and delete button
                if ImGui.BeginTable('GroupsList', 2, ImGuiTableFlags.None) then
                    ImGui.TableSetupColumn('Name', ImGuiTableColumnFlags.WidthStretch)
                    ImGui.TableSetupColumn('Del', ImGuiTableColumnFlags.WidthFixed, 25)
                    
                    for i, gname in ipairs(groupNames) do
                        ImGui.TableNextRow()
                        
                        -- Group name column
                        ImGui.TableNextColumn()
                        local selected = (B.selected == gname)
                        -- Don't span columns so delete button is clickable
                        if ImGui.Selectable(gname .. '##sel_' .. i, selected, ImGuiSelectableFlags.None) then 
                            B.selected = gname
                        end
                        
                        -- Delete button column
                        ImGui.TableNextColumn()
                        ImGui.PushStyleColor(ImGuiCol.Button, 0.7, 0.2, 0.2, 0.8)
                        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.8, 0.3, 0.3, 0.9)
                        ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.9, 0.4, 0.4, 1.0)
                        
                        if ImGui.Button('X##del_' .. i, 20, 20) then
                            deletedName = gname
                        end
                        
                        ImGui.PopStyleColor(3)
                        
                        if ImGui.IsItemHovered() then
                            ImGui.SetTooltip('Delete group "' .. gname .. '"')
                        end
                    end
                    
                    ImGui.EndTable()
                end
            end
            ImGui.EndChild()
            
            if deletedName then
                print(string.format('[BotControls] Deleted group: "%s"', deletedName))
                B.groups[deletedName] = nil
                if B.selected == deletedName then B.selected = nil end
                _batch_save()
            end

            -- New group
            ImGui.Separator()
            ImGui.Text('New Group:')
            local ng = ImGui.InputText('##new_group', B.newGroupName or '')
            if ng ~= nil then B.newGroupName = ng end
            ImGui.SameLine()
            if ImGui.SmallButton('+') then
                local name = tostring(B.newGroupName or '')
                if name ~= '' and not B.groups[name] then 
                    B.groups[name] = {}
                    B.selected = name
                    B.newGroupName=''
                    _batch_save()
                    print(string.format('[BotControls] Created new group: "%s"', name))
                end
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Create a new empty group with the entered name')
            end

            -- Quick type sets (stacked buttons)
            ImGui.Separator()
            ImGui.Text('Quick Add by Type:')
            if not B.selected then
                ImGui.TextColored(0.7, 0.7, 0.7, 1.0, '(Select a group first)')
            else
                local function add_by_classes(classList)
                    B.groups[B.selected] = B.groups[B.selected] or {}
                    local set = {}
                    for _,n in ipairs(B.groups[B.selected]) do set[n]=true end
                    for _, n in ipairs(names) do
                        local cls = _getBotClass(n)
                        for _, c in ipairs(classList) do
                            if cls == c then set[n]=true end
                        end
                    end
                    local out = {}
                    for n,_ in pairs(set) do table.insert(out, n) end
                    table.sort(out, function(a,b) return a:lower()<b:lower() end)
                    B.groups[B.selected] = out; _batch_save()
                end
                if ImGui.SmallButton('Tanks') then add_by_classes({'Warrior','Paladin','Shadowknight'}) end
                if ImGui.IsItemHovered() then ImGui.SetTooltip('Warriors, Paladins, Shadowknights') end
                if ImGui.SmallButton('Healers') then add_by_classes({'Cleric','Druid','Shaman'}) end
                if ImGui.IsItemHovered() then ImGui.SetTooltip('Clerics, Druids, Shamans') end
                if ImGui.SmallButton('Casters') then add_by_classes({'Necromancer','Wizard','Magician','Enchanter'}) end
                if ImGui.IsItemHovered() then ImGui.SetTooltip('Necromancers, Wizards, Magicians, Enchanters') end
                if ImGui.SmallButton('Melee') then add_by_classes({'Monk','Rogue','Bard','Beastlord','Berserker','Ranger'}) end
                if ImGui.IsItemHovered() then ImGui.SetTooltip('Monks, Rogues, Bards, Beastlords, Berserkers, Rangers') end
                if ImGui.SmallButton('Pet Users') then add_by_classes({'Magician','Necromancer','Beastlord','Shadowknight'}) end
                if ImGui.IsItemHovered() then ImGui.SetTooltip('Magicians, Necromancers, Beastlords, Shadowknights') end
                if ImGui.SmallButton('Support') then add_by_classes({'Bard','Enchanter'}) end
                if ImGui.IsItemHovered() then ImGui.SetTooltip('Bards, Enchanters') end
            end
        end
        ImGui.EndChild()

        ImGui.SameLine()

        -- Right: Bots list and group detail
        if ImGui.BeginChild('BatchRight', 0, 0, true) then
            -- All bots with filter and simple list
            ImGui.TextColored(0.95, 0.85, 0.2, 1.0, string.format('All Bots (%d)', #names))
            local filter = tostring(B.filterText or ''):lower()

            -- Context menu to toggle multi-select
            if ImGui.BeginPopupContextWindow('BatchRightCtx', 1) then
                local ms = B.multiSelecting and true or false
                local newVal, pressed = ImGui.Checkbox('Multi-select mode', ms)
                if pressed then B.multiSelecting = newVal and true or false end
                if ImGui.MenuItem('Clear Selection') then B.selectionSet = {} end
                ImGui.EndPopup()
            end

            -- Multi-select status + action
            if B.multiSelecting then
                ImGui.TextColored(0.7, 0.9, 0.7, 1.0, 'Multi-select: ON')
                if B.selected then
                    ImGui.SameLine()
                    if ImGui.SmallButton('Add Selected') then
                        B.groups[B.selected] = B.groups[B.selected] or {}
                        local set = {}
                        for _, m in ipairs(B.groups[B.selected]) do set[m]=true end
                        for name,_ in pairs(B.selectionSet or {}) do set[name]=true end
                        local out = {}
                        for n,_ in pairs(set) do table.insert(out, n) end
                        table.sort(out, function(a,b) return a:lower()<b:lower() end)
                        B.groups[B.selected] = out
                        B.selectionSet = {}
                        _batch_save()
                    end
                    if ImGui.IsItemHovered() then
                        ImGui.SetTooltip('Add selected bots to group "' .. B.selected .. '"')
                    end
                end
            end

            ImGui.Separator()

            -- Bot list in a scrollable child
            local availX, availY = ImGui.GetContentRegionAvail()
            local botListHeight = math.max(120, (availY or 200) * 0.5)
            if ImGui.BeginChild('BotListScroll', 0, botListHeight, true) then
                B.selectionSet = B.selectionSet or {}
                for _, n in ipairs(names) do
                    if filter == '' or n:lower():find(filter, 1, true) then
                        local label = string.format('%s  [%s]', n, _getClassAbbrev(n))
                        local selected = B.selectionSet[n] and true or false
                        if ImGui.Selectable(label, selected) then
                            if B.multiSelecting then
                                B.selectionSet[n] = not selected or nil
                            else
                                if B.selected then
                                    B.groups[B.selected] = B.groups[B.selected] or {}
                                    local exists = false
                                    for _, m in ipairs(B.groups[B.selected]) do if m == n then exists = true; break end end
                                    if not exists then 
                                        table.insert(B.groups[B.selected], n)
                                        _batch_save()
                                    end
                                end
                            end
                        end
                        if ImGui.IsItemHovered() and not B.multiSelecting then
                            if B.selected then
                                ImGui.SetTooltip('Click to add ' .. n .. ' to group "' .. B.selected .. '"')
                            else
                                ImGui.SetTooltip('Select a group first, then click to add bots')
                            end
                        end
                    end
                end
            end
            ImGui.EndChild()

            ImGui.Separator()
            -- Selected group detail
            ImGui.TextColored(0.95, 0.85, 0.2, 1.0, string.format('Selected Group: %s', tostring(B.selected or '<none>')))
            if B.selected and B.groups[B.selected] then
                local members = B.groups[B.selected]
                table.sort(members, function(a,b) return a:lower() < b:lower() end)

                -- Height for members table area (use most of remaining space)
                local availX, availY = ImGui.GetContentRegionAvail()
                local areaH = availY or 200
                local tableH = math.max(120, areaH - 90)

                ImGui.Text(string.format('Members (%d):', #members))
                if ImGui.BeginChild('GroupMembersScroll', 0, tableH, true) then
                    local grpTableFlags = bit32.bor(ImGuiTableFlags.Borders, ImGuiTableFlags.RowBg, ImGuiTableFlags.Resizable)
                if ImGui.BeginTable('BatchGroupMembers', 2, grpTableFlags) then
                        ImGui.TableSetupColumn('Name', ImGuiTableColumnFlags.WidthStretch)
                        ImGui.TableSetupColumn('Remove', ImGuiTableColumnFlags.WidthFixed, 50)
                        ImGui.TableHeadersRow()
                        local toremove = nil
                        for _, n in ipairs(members) do
                            ImGui.TableNextRow()
                            ImGui.TableNextColumn(); ImGui.Text(n)
                            ImGui.TableNextColumn();
                            if ImGui.SmallButton('X##rm_'..n) then toremove = n end
                            if ImGui.IsItemHovered() then
                                ImGui.SetTooltip('Remove ' .. n .. ' from group')
                            end
                        end
                        ImGui.EndTable()
                        if toremove then
                            local newlist = {}
                            for _, n in ipairs(members) do if n ~= toremove then table.insert(newlist, n) end end
                            B.groups[B.selected] = newlist
                            _batch_save()
                        end
                    end
                end
                ImGui.EndChild()

                ImGui.Separator()
                ImGui.Text('Command to send:')
                local cmdNew = ImGui.InputText('##batch_cmd', B.commandText or '')
                if cmdNew ~= nil then B.commandText = cmdNew end
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Enter a command like ^stance 2 target, ^follow reset target, etc.')
                end
                if ImGui.Button('Queue to Group', 120, 0) then
                    local cmd = tostring(B.commandText or '')
                    if cmd ~= '' then
                        for i, n in ipairs(B.groups[B.selected]) do
                            _enqueue(function()
                                _targetBotByName(n)
                                mq.delay(B.queueDelayMs or 75)
                                mq.cmd(string.format('/say %s', cmd))
                            end)
                        end
                        print(string.format('[BotControls] Queued command "%s" to %d bots in group "%s"', cmd, #members, B.selected))
                    end
                end
            end
        end
        ImGui.EndChild()
    end
    -- Close BatchSplit child
    ImGui.EndChild()
end

return M
