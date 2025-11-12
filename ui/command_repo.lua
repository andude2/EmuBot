local mq = require('mq')
local Icons = require('mq.icons')

-- New repository of Bot Command Buttons built from user's ^help dump
-- API-compatible with the previous module
-- Exposes: register, register_many, get, list, search, execute

local M = {}

-- Core items we must preserve for existing hotbar defaults
-- Keep the original behavior and labels
M.items = {
    {
        id = 'attack_spawned',
        label = 'Attack',
        icon = Icons.FA_CROSSHAIRS or Icons.FA_BOLT,
        category = 'Combat',
        description = 'Attack the currently spawned target (^attack spawned)',
        actions = {
            {type='cmd', text='/say ^attack spawned'},
        },
    },
    {
        id = 'backoff',
        label = 'Backoff',
        icon = Icons.FA_UNDO or Icons.FA_ARROW_LEFT,
        category = 'Combat',
        description = 'Release and re-summon bots to break engagement',
        actions = {
            {type='cmd', text='/say ^release spawned'},
            {type='cmd', text='/say ^botsummon spawned'},
        },
    },
    {
        id = 'hold',
        label = 'Hold',
        icon = Icons.FA_HAND_PAPER or Icons.FA_PAUSE,
        category = 'Combat',
        description = 'Release and re-summon (hold position logic)',
        actions = {
            {type='cmd', text='/say ^release spawned'},
            {type='cmd', text='/say ^botsummon spawned'},
        },
    },
    {
        id = 'guard_here',
        label = 'Guard Here',
        icon = Icons.FA_SHIELD or Icons.FA_MAP_MARKER,
        category = 'Camp',
        description = 'Summon then guard at current spot',
        actions = {
            {type='cmd', text='/say ^botsummon spawned'},
            {type='delay', ms=500},
            {type='cmd', text='/say ^guard spawned'},
        },
    },
    {
        id = 'clearcamp_callback',
        label = 'ClearCampCallback',
        icon = Icons.FA_BROOM or Icons.FA_TIMES,
        category = 'Camp',
        description = 'Clear guard camp then re-summon',
        actions = {
            {type='cmd', text='/say ^guard clear spawned'},
            {type='delay', ms=500},
            {type='cmd', text='/say ^botsummon spawned'},
        },
    },
    {
        id='auto_assist_toggle',
        label = 'Auto Assist',
        icon = Icons.FA_ADJUST or Icons.FA_TOGGLE_ON,
        category = 'Assist',
        description = 'Toggle autodefend (^oo autodefend)',
        actions = {
            {type='cmd', text='/say ^oo autodefend'},
        },
    },
    {
        id = 'summon_to_me',
        label = 'Summon',
        icon = Icons.FA_MAGNET or Icons.FA_USERS,
        category = 'Camp',
        description = 'Summon bots to me',
        actions = {
            {type='cmd', text='/say ^botsummon spawned'},
        },
    },
    {
        id = 'spawn_missing_party_bots',
        label = 'Missing?',
        icon = Icons.FA_USER_PLUS or Icons.FA_USERS,
        category = 'Management',
        description = 'Spawn any missing bots from your current raid (preferred) or group. Does nothing if solo.',
        actions = {},
    },
}

-- HELP dump extracted from user log (deduplicated by command token below)
-- Format: ^command - description
local HELP_TEXT = [[
^? - List available commands and their description - specify partial command as argument to search
^actionable - Lists actionable command arguments and use descriptions
^aggrochecks - Toggles whether or not bots will cast a spell type if they think it will get them aggro
^alias - Find available aliases for a bot command
^announcecasts - Turn on or off cast announcements by spell type
^app - Lists the available bot appearance [subcommands]
^appearance - Lists the available bot appearance [subcommands]
^applypoison - Applies cursor-held poison to a rogue bot's weapon
^atk - Orders bots to attack a designated target
^attack - Orders bots to attack a designated target
^b - Lists the available bot management [subcommands]
^bc - Changes the beard color of a bot
^beardcolor - Changes the beard color of a bot
^beardstyle - Changes the beard style of a bot
^behindmob - Toggles whether or not your bot tries to stay behind a mob
^bh - Toggles whether or not your bot tries to stay behind a mob
^blockedbuffs - Set, view and clear blocked buffs for the selected bot(s)
^blockedpetbuffs - Set, view and clear blocked pet buffs for the selected bot(s)
^bot - Lists the available bot management [subcommands]
^botappearance - Lists the available bot appearance [subcommands]
^botbeardcolor - Changes the beard color of a bot
^botbeardstyle - Changes the beard style of a bot
^botcamp - Orders a bot(s) to camp
^botcreate - Creates a new bot
^botdelete - Deletes all record of a bot
^botdetails - Changes the Drakkin details of a bot
^botdyearmor - Changes the color of a bot's (bots') armor
^boteyes - Changes the eye colors of a bot
^botface - Changes the facial appearance of your bot
^botfollowdistance - Changes the follow distance(s) of a bot(s)
^bothaircolor - Changes the hair color of a bot
^bothairstyle - Changes the hairstyle of a bot
^botheritage - Changes the Drakkin heritage of a bot
^botinspectmessage - Changes the inspect message of a bot
^botlist - Lists the bots that you own
^botreport - Orders a bot to report its readiness
^botsettings - Lists settings related to spell types and bot combat
^botspawn - Spawns a created bot
^botstance - Changes the stance of a bot
^botstopmeleelevel - Sets the level a caster or spell-casting fighter bot will stop melee combat
^botsuffix - Sets a bots suffix
^botsummon - Summons bot(s) to your location
^botsurname - Sets a bots surname (last name)
^bottattoo - Changes the Drakkin tattoo of a bot
^bottitle - Sets a bots title
^bottogglehelm - Toggles the helm visibility of a bot between shown and hidden
^bottoggleranged - Toggles a ranged bot between melee and ranged weapon use
^botupdate - Updates a bot to reflect any level changes that you have experienced
^botwoad - Changes the Barbarian woad of a bot
^bs - Changes the beard style of a bot
^btr - Toggles a ranged bot between melee and ranged weapon use
^camp - Orders a bot(s) to camp
^cast - Tells the first found specified bot to cast the given spell type
^classracelist - Lists the classes and races and their appropriate IDs
^clickitem - Orders your targeted bot to click the item in the provided inventory slot.
^copy - Copies settings from one bot to another
^copysettings - Copies settings from one bot to another
^create - Creates a new bot
^default - Restores a bot back to default settings
^defaultsettings - Restores a bot back to default settings
^delays - Controls the delay between casts for a specific spell type
^delete - Deletes all record of a bot
^dep - Orders a bot to open a magical doorway to a specified destination
^depart - Orders a bot to open a magical doorway to a specified destination
^details - Changes the Drakkin details of a bot
^disc - Uses aggressive/defensive disciplines or can specify spell ID
^discipline - Uses aggressive/defensive disciplines or can specify spell ID
^distanceranged - Controls the range casters and ranged will try to stay away from a mob
^distranged - Controls the range casters and ranged will try to stay away from a mob
^dr - Controls the range casters and ranged will try to stay away from a mob
^dyearmor - Changes the color of a bot's (bots') armor
^enforce - Toggles your Bot to cast only spells in their spell settings list.
^enforcespellsettings - Toggles your Bot to cast only spells in their spell settings list.
^engagedpriority - Controls the order of casts by spell type when engaged in combat
^eyes - Changes the eye colors of a bot
^face - Changes the facial appearance of your bot
^findaliases - Find available aliases for a bot command
^follow - Orders bots to follow a designated target (option 'chain' auto-links eligible spawned bots)
^followd - Changes the follow distance(s) of a bot(s)
^followdistance - Changes the follow distance(s) of a bot(s)
^guard - Orders bots to guard their current positions
^haircolor - Changes the hair color of a bot
^hairstyle - Changes the hairstyle of a bot
^hc - Changes the hair color of a bot
^healrotation - Lists the available bot heal rotation [subcommands]
^healrotationadaptivetargeting - Enables or disables adaptive targeting within the heal rotation instance
^healrotationaddmember - Adds a bot to a heal rotation instance
^healrotationaddtarget - Adds target to a heal rotation instance
^healrotationadjustcritical - Adjusts the critial HP limit of the heal rotation instance's Class Armor Type criteria
^healrotationadjustsafe - Adjusts the safe HP limit of the heal rotation instance's Class Armor Type criteria
^healrotationcastingoverride - Enables or disables casting overrides within the heal rotation instance
^healrotationchangeinterval - Changes casting interval between members within the heal rotation instance
^healrotationclearhot - Clears the HOT of a heal rotation instance
^healrotationcleartargets - Removes all targets from a heal rotation instance
^healrotationcreate - Creates a bot heal rotation instance and designates a leader
^healrotationdelete - Deletes a bot heal rotation entry by leader
^healrotationfastheals - Enables or disables fast heals within the heal rotation instance
^healrotationlist - Reports heal rotation instance(s) information
^healrotationremovemember - Removes a bot from a heal rotation instance
^healrotationremovetarget - Removes target from a heal rotations instance
^healrotationresetlimits - Resets all Class Armor Type HP limit criteria in a heal rotation to its default value
^healrotationsave - Saves a bot heal rotation entry by leader
^healrotationsethot - Sets the HOT in a heal rotation instance
^healrotationstart - Starts a heal rotation
^healrotationstop - Stops a heal rotation
^health - Orders a bot to report its readiness
^helm - Toggles the helm visibility of a bot between shown and hidden
^help - List available commands and their description - specify partial command as argument to search
^her - Changes the Drakkin heritage of a bot
^heritage - Changes the Drakkin heritage of a bot
^hold - Prevents a bot from attacking until released
^holds - Controls whether a bot holds the specified spell type or not
^hr - Lists the available bot heal rotation [subcommands]
^hradapt - Enables or disables adaptive targeting within the heal rotation instance
^hraddm - Adds a bot to a heal rotation instance
^hraddt - Adds target to a heal rotation instance
^hrclear - Removes all targets from a heal rotation instance
^hrclearhot - Clears the HOT of a heal rotation instance
^hrcreate - Creates a bot heal rotation instance and designates a leader
^hrcrit - Adjusts the critial HP limit of the heal rotation instance's Class Armor Type criteria
^hrdelete - Deletes a bot heal rotation entry by leader
^hrfastheals - Enables or disables fast heals within the heal rotation instance
^hrinterval - Changes casting interval between members within the heal rotation instance
^hrlist - Reports heal rotation instance(s) information
^hroverride - Enables or disables casting overrides within the heal rotation instance
^hrremm - Removes a bot from a heal rotation instance
^hrremt - Removes target from a heal rotations instance
^hrreset - Resets all Class Armor Type HP limit criteria in a heal rotation to its default value
^hrsafe - Adjusts the safe HP limit of the heal rotation instance's Class Armor Type criteria
^hrsave - Saves a bot heal rotation entry by leader
^hrsethot - Sets the HOT in a heal rotation instance
^hrstart - Starts a heal rotation
^hrstop - Stops a heal rotation
^hs - Changes the hairstyle of a bot
^ib - Control whether or not illusion effects will land on the bot if casted by another player or bot
^idlepriority - Controls the order of casts by spell type when out of combat
^ig - Gives the item on your cursor to a bot
^il - Lists all items in a bot's inventory
^illusionblock - Control whether or not illusion effects will land on the bot if casted by another player or bot
^inspect - Changes the inspect message of a bot
^inv - Lists the available bot inventory [subcommands]
^inventory - Lists the available bot inventory [subcommands]
^inventorygive - Gives the item on your cursor to a bot
^inventorylist - Lists all items in a bot's inventory
^inventoryremove - Removes an item from a bot's inventory
^inventorywindow - Displays all items in a bot's inventory in a pop-up window
^invgive - Gives the item on your cursor to a bot
^invlist - Lists all items in a bot's inventory
^invremove - Removes an item from a bot's inventory
^invwindow - Displays all items in a bot's inventory in a pop-up window
^ir - Removes an item from a bot's inventory
^itemuse - Elicits a report from spawned bots that can use the item on your cursor (option 'empty' yields only empty slots)
^iu - Elicits a report from spawned bots that can use the item on your cursor (option 'empty' yields only empty slots)
^iw - Displays all items in a bot's inventory in a pop-up window
^lastname - Sets a bots surname (last name)
^list - Lists the bots that you own
^mana - Orders a bot to report its readiness
^maxhp - Controls at what HP percent a bot will stop casting different spell types
^maxmana - Controls at what mana percent a bot will stop casting different spell types
^maxmeleerange - Toggles whether your bot is at max melee range or not. This will disable all special abilities, including taunt.
^maxthresholds - Controls the minimum target HP threshold for a spell to be cast for a specific type
^minhp - Controls at what HP percent a bot will start casting different spell types
^minmana - Controls at what mana percent a bot will start casting different spell types
^minthresholds - Controls the maximum target HP threshold for a spell to be cast for a specific type
^mmr - Toggles whether your bot is at max melee range or not. This will disable all special abilities, including taunt.
^oo - Sets options available to bot owners
^owneroption - Sets options available to bot owners
^p - Lists the available bot pet [subcommands]
^pet - Lists the available bot pet [subcommands]
^petgetlost - Orders a bot to remove its summoned pet
^petremove - Orders a bot to remove its charmed pet
^petsettype - Orders a Magician bot to use a specified pet type
^pgl - Orders a bot to remove its summoned pet
^picklock - Orders a capable bot to pick the lock of the closest door
^pickpocket - Orders a capable bot to pickpocket a NPC
^pl - Orders a capable bot to pick the lock of the closest door
^poison - Applies cursor-held poison to a rogue bot's weapon
^pp - Orders a capable bot to pickpocket a NPC
^precombat - Sets flag used to determine pre-combat behavior
^prem - Orders a bot to remove its charmed pet
^pset - Orders a Magician bot to use a specified pet type
^pst - Orders a Magician bot to use a specified pet type
^pull - Orders a designated bot to 'pull' an enemy
^pursuepriority - Controls the order of casts by spell type when pursuing in combat
^ranged - Toggles a ranged bot between melee and ranged weapon use
^release - Releases a suspended bot's AI processing (with hate list wipe)
^report - Orders a bot to report its readiness
^resistlimits - Controls the resist limits for bots to cast spells on their target
^setassistee - Sets your target to be the person your bots assist. Bots will always assist you before others
^settings - Lists settings related to spell types and bot combat
^sitcombat - Toggles whether or a not a bot will attempt to med or sit to heal in combat
^sithp - HP threshold for a bot to start sitting in combat if allowed
^sithppercent - HP threshold for a bot to start sitting in combat if allowed
^sitincombat - Toggles whether or a not a bot will attempt to med or sit to heal in combat
^sitmana - Mana threshold for a bot to start sitting in combat if allowed
^sitmanapercent - Mana threshold for a bot to start sitting in combat if allowed
^sml - Sets the level a caster or spell-casting fighter bot will stop melee combat
^spawn - Spawns a created bot
^spellaggrochecks - Toggles whether or not bots will cast a spell type if they think it will get them aggro
^spellannouncecasts - Turn on or off cast announcements by spell type
^spelldelays - Controls the delay between casts for a specific spell type
^spellengagedpriority - Controls the order of casts by spell type when engaged in combat
^spellholds - Controls whether a bot holds the specified spell type or not
^spellidlepriority - Controls the order of casts by spell type when out of combat
^spellinfo - Opens a dialogue window with spell info
^spellmaxhppct - Controls at what HP percent a bot will stop casting different spell types
^spellmaxmanapct - Controls at what mana percent a bot will stop casting different spell types
^spellmaxthresholds - Controls the minimum target HP threshold for a spell to be cast for a specific type
^spellminhppct - Controls at what HP percent a bot will start casting different spell types
^spellminmanapct - Controls at what mana percent a bot will start casting different spell types
^spellminthresholds - Controls the maximum target HP threshold for a spell to be cast for a specific type
^spellpursuepriority - Controls the order of casts by spell type when pursuing in combat
^spellresistlimits - Controls the resist limits for bots to cast spells on their target
^spells - Lists all Spells learned by the Bot.
^spellsettings - Lists a bot's spell setting entries
^spellsettingsadd - Add a bot spell setting entry
^spellsettingsdelete - Delete a bot spell setting entry
^spellsettingstoggle - Toggle a bot spell use
^spellsettingsupdate - Update a bot spell setting entry
^spelltargetcount - Sets the required target amount for group/AE spells by spell type
^spelltypeids - Lists spelltypes by ID
^spelltypenames - Lists spelltypes by shortname
^stance - Changes the stance of a bot
^suffix - Sets a bots suffix
^summon - Summons bot(s) to your location
^suspend - Suspends a bot's AI processing until released
^targetcount - Sets the required target amount for group/AE spells by spell type
^tattoo - Changes the Drakkin tattoo of a bot
^taunt - Toggles taunt use by a bot
^title - Sets a bots title
^togglehelm - Toggles the helm visibility of a bot between shown and hidden
^toggleranged - Toggles a ranged bot between melee and ranged weapon use
^track - Orders a capable bot to track enemies
^update - Updates a bot to reflect any level changes that you have experienced
^vc - Views bot race class combinations
^viewcombos - Views bot race class combinations
^woad - Changes the Barbarian woad of a bot
]]

-- Heuristic categorization based on command token
local function categorize(cmd, desc)
    cmd = tostring(cmd or ''):lower()
    local function starts(prefix) return cmd:sub(1, #prefix) == prefix end
    local function any(prefixes)
        for _,p in ipairs(prefixes) do if starts(p) then return true end end
        return false
    end

    if any({'healrotation','hr'}) then return 'Heals' end
    if any({'spellsettings','spelldelays','spellengagedpriority','spellidlepriority','spellpursuepriority','spellresistlimits','spellmax','spellmin','spelltargetcount','spelltype','spells','spellinfo','spell'}) then return 'Spells' end
    if any({'pet','pgl','prem','pset','pst','p '}) or cmd=='p' then return 'Pet' end
    if any({'inv','inventory','ig','il','iw','ir','clickitem','itemuse'}) then return 'Inventory' end
    if any({'bot','b '}) or cmd=='b' or cmd=='owneroption' or cmd=='settings' or cmd=='update' or cmd=='create' or cmd=='delete' or cmd=='default' or cmd=='defaultsettings' or cmd=='copy' or cmd=='copysettings' or cmd=='list' or cmd=='report' or cmd=='help' then return 'Management' end
    if any({'appearance','botappearance','beard','hair','eyes','face','heritage','details','tattoo','woad'}) or cmd=='helm' or cmd=='togglehelm' or cmd=='bottitle' or cmd=='title' or cmd=='suffix' or cmd=='botsuffix' or cmd=='lastname' or cmd=='botsurname' or cmd=='botinspectmessage' or cmd=='inspect' then return 'Appearance' end
    if cmd=='follow' or starts('followd') or starts('followdistance') then return 'Follow' end
    if cmd=='guard' or cmd=='camp' or cmd=='botsummon' or cmd=='summon' then return 'Camp' end
    if cmd=='attack' or cmd=='atk' or cmd=='hold' or cmd=='release' or cmd=='pull' or cmd=='taunt' or cmd=='ranged' or cmd=='maxmeleerange' or cmd=='mmr' or cmd=='cast' or cmd=='disc' or cmd=='discipline' then return 'Combat' end
    if cmd=='dep' or cmd=='depart' or cmd=='track' then return 'Utility' end
    if cmd=='setassistee' or cmd=='oo' then return 'Assist' end
    if cmd=='aggrochecks' or cmd=='announcecasts' or cmd=='enforce' or cmd=='enforcespellsettings' or cmd=='engagedpriority' or cmd=='idlepriority' or cmd=='pursuepriority' or cmd=='holds' or cmd=='precombat' or cmd=='sithp' or cmd=='sithppercent' or cmd=='sitincombat' or cmd=='sitcombat' or cmd=='sitmana' or cmd=='sitmanapercent' or cmd=='maxhp' or cmd=='minhp' or cmd=='maxmana' or cmd=='minmana' or cmd=='targetcount' or cmd=='resistlimits' or cmd=='suspend' then return 'Behavior' end
    if cmd=='classracelist' or cmd=='viewcombos' or cmd=='vc' or cmd=='findaliases' or cmd=='alias' or cmd=='actionable' or cmd=='?' then return 'Info' end
    if cmd=='mana' or cmd=='health' then return 'Info' end
    return 'Uncategorized'
end

-- Build repo from HELP_TEXT
local seen = {}
for line in HELP_TEXT:gmatch("[^\r\n]+") do
    local cmd, desc = line:match("%^(%S+)%s*%-%s*(.+)")
    if not cmd then cmd = line:match("%^(%S+)") end
    if cmd and not seen[cmd] then
        seen[cmd] = true
        local item = {
            id = cmd,
            label = '^'..cmd,
            icon = nil,
            category = categorize(cmd, desc),
            description = desc or '',
            actions = { {type='cmd', text='/say ^'..cmd} },
        }
        table.insert(M.items, item)
    end
end

-- Maps and custom registry (compatible API)
M.map = {}
M.custom = {}
M.custom_map = {}
for _, it in ipairs(M.items) do M.map[it.id] = it end

function M.register(item)
    if not item or not item.id then return false end
    local it = {}
    for k,v in pairs(item) do it[k]=v end
    M.custom[it.id] = it
    M.custom_map[it.id] = it
    return true
end

function M.register_many(list)
    if type(list) ~= 'table' then return end
    for _, it in pairs(list) do M.register(it) end
end

function M.get(id)
    return M.custom_map[id] or M.map[id]
end

function M.list()
    local out = {}
    for _, it in ipairs(M.items) do table.insert(out, it) end
    for _, it in pairs(M.custom) do table.insert(out, it) end
    return out
end

function M.search(query)
    local all = M.list()
    if not query or query == '' then return all end
    local q = query:lower()
    local out = {}
    for _, it in ipairs(all) do
        local hay = (it.label or '') .. ' ' .. (it.description or '') .. ' ' .. (it.category or '')
        if hay:lower():find(q, 1, true) then table.insert(out, it) end
    end
    return out
end

function M.execute(item)
    if not item or not item.actions then return end
    for _, a in ipairs(item.actions) do
        if a.type == 'cmd' and a.text then
            mq.cmd(a.text)
        elseif a.type == 'delay' and a.ms then
            mq.delay(tonumber(a.ms) or 0)
        end
    end
end

return M
