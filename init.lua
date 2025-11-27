local mq = require('mq')
local ImGui = require('ImGui')

local bot_inventory = require('modules.bot_inventory')
local bot_management = require('modules.bot_management')
local bot_groups = require('modules.bot_groups')
local raid_manager = require('modules.raid_manager')
local upgrade = require('modules.upgrade')
local db = require('modules.db')
local commandsui = require('ui.commandsui')
local bot_controls = require('ui.bot_controls')
local raid_hud = require('ui.raid_hud')
local applyTableSort = require('modules.ui_table_utils').applyTableSort

-- EmuBot UI style helpers: round all relevant UI elements at radius 8
local function EmuBot_PushRounding()
    ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.GrabRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.TabRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.PopupRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarRounding, 8)
end

local function EmuBot_PopRounding()
    -- Pop all style vars pushed above (must remain in sync)
    ImGui.PopStyleVar(7)
end

local function printf(fmt, ...)
    if mq.printf then
        mq.printf(fmt, ...)
    else
        print(string.format(fmt, ...))
    end
end
local function refreshBotList()
    if not bot_inventory or not bot_inventory.refreshBotList then return end
    bot_inventory.refreshBotList()
end

local EQ_ICON_OFFSET = 500
local ICON_WIDTH = 20
local ICON_HEIGHT = 20
local animItems = mq.FindTextureAnimation('A_DragItem')

local botUI = {
    showWindow = false,
    botFetchDelay = 1.0,
    botSpawnDelay = 2.0,
    botTargetDelay = 1.0,
    viewerShowClassInSelector = false,
    selectedBot = nil,
    selectedBotSlotID = nil,
    selectedBotSlotName = nil,
    _botInventoryFetchQueue = {},
    _botInventoryFetchSet = {},
    _botInventoryFetchActive = false,
    _botInventoryLastAttempt = {},
    _botListRequested = false,
    _scanQueue = {},
    _scanActive = false,
    deferred_tasks = {},
    lastExportMessage = nil,
    lastExportWasSuccess = false,
    -- Scan All Bots functionality
    _scanAllActive = false,
    _scanAllQueue = {},
    _scanAllCurrentBot = nil,
    _scanAllBotIndex = 0,
    _scanAllStartTime = nil,
    _scanAllProgress = '',
    _scanAllTotalItems = 0,
    -- Floating toggle button
    showFloatingToggle = true,
    floatingPosX = 60,
    floatingPosY = 60,
    floatingButtonSize = 50,
    -- Floating ^iu quick button
    showUpgradeFloating = true,
    upgradePosX = 120,
    upgradePosY = 60,
    upgradeButtonSize = 50,
    closeUpgradeWindowOnSwap = true,
    -- Local inventory comparison
    localInventoryCache = nil,
    localInventoryCacheTime = 0,
    localInventoryCacheDuration = 60, -- Cache duration in seconds
    showLocalCompareWindow = false,
    localCompareItems = {},
    rightClickedBotItem = nil,
    -- Bot failure tracking
    _botFailureCount = {}, -- Track failed bots with attempt count
    _maxFailures = 3, -- Max attempts before skipping a bot
    _failureTimeout = 300, -- 5 minutes before allowing retry of failed bot
    _skippedBots = {}, -- Track skipped bots with timestamp
    -- Camp control during scan all
    disableCampDuringScanAll = false, -- When true, don't camp bots during scan all
    -- Camp control during scan all
    _originalCampSetting = false, -- Track original camp setting
    -- Auto-scan tracking
    _autoScannedItems = 0, -- Track items auto-scanned due to mismatches,
    -- Visual tab options
    showClassInVisual = false,
    -- Selector options
    viewerAppendClassAbbrevInSelector = false,
    -- Cache of item stats keyed by itemID to avoid duplicate scans per session
    _itemStatCache = {},
    -- Database maintenance status
    lastPurgeMessage = nil,
    lastPurgeWasSuccess = false,
}

if upgrade and upgrade.set_close_window_on_swap then
    upgrade.set_close_window_on_swap(botUI.closeUpgradeWindowOnSwap)
end

-- Forward declare helpers referenced before their definitions
local get_bot_class_abbrev

local function drawItemIcon(iconID, width, height)
    width = width or ICON_WIDTH
    height = height or ICON_HEIGHT
    if iconID and iconID > 0 and animItems then
        animItems:SetTextureCell(iconID - EQ_ICON_OFFSET)
        ImGui.DrawTextureAnimation(animItems, width, height)
    else
        ImGui.Text('N/A')
    end
end

local function enqueueTask(fn)
    table.insert(botUI.deferred_tasks, fn)
end

-- Expose enqueueTask so other modules can schedule non-blocking actions
_G.enqueueTask = enqueueTask

local function processDeferredTasks()
    if #botUI.deferred_tasks == 0 then return end
    local task = table.remove(botUI.deferred_tasks, 1)
    local ok, err = pcall(task)
    if not ok then
        printf('[EmuBot] Deferred task error: %s', tostring(err))
    end
end


local function captureDisplayItemIcon(target)
    if not target then return end
    local displayItem = mq.TLO.DisplayItem
    if displayItem and displayItem() then
        local iconValue = tonumber(displayItem.Icon() or 0) or 0
        if iconValue > 0 then
            target.icon = iconValue
            target.iconID = iconValue
        end
    end
end

local function captureAugmentData(target)
    if not target then return false end
    local displayItem = mq.TLO.DisplayItem
    if not displayItem or not displayItem() then return false end

    local baseItem = displayItem.Item
    if not baseItem or not baseItem() then return false end

    local success = false

    for augIndex = 1, 6 do
        local nameField = 'aug' .. augIndex .. 'Name'
        local linkField = 'aug' .. augIndex .. 'link'
        local iconField = 'aug' .. augIndex .. 'Icon'

        local augTLO
        local ok, result = pcall(function()
            if baseItem.Item then
                return baseItem.Item(augIndex)
            end
            return nil
        end)
        if ok then augTLO = result end

        local name, link, icon = nil, nil, nil
        local augIsValid = false
        if augTLO then
            ok, augIsValid = pcall(function()
                local value = augTLO()
                return value ~= nil and value ~= ''
            end)
            if not ok then augIsValid = false end
        end

        if augTLO and augIsValid then
            ok, name = pcall(function()
                if augTLO.Name then
                    return augTLO.Name()
                end
                return nil
            end)
            if not ok then name = nil end
            ok, link = pcall(function()
                if augTLO.ItemLink then
                    return augTLO.ItemLink()
                end
                return nil
            end)
            if not ok then link = nil end
            ok, icon = pcall(function()
                if augTLO.Icon then
                    return tonumber(augTLO.Icon() or 0) or 0
                end
                return 0
            end)
            if not ok then icon = nil end
        end

        if name and name ~= '' then
            target[nameField] = name
            target[linkField] = link and link ~= '' and link or nil
            target[iconField] = icon or 0
            success = true
        else
            target[nameField] = nil
            target[linkField] = nil
            target[iconField] = nil
        end
    end

    return success
end

local function getDisplayItemNumber(accessor)
    if not accessor then return 0 end
    local ok, value = pcall(function()
        local result = accessor()
        return tonumber(result) or 0
    end)
    if ok and value then return value end
    return 0
end

local function populateStatsFromDisplayItem(target)
    if not target then return false, false end

    local displayItem = mq.TLO.DisplayItem
    if not displayItem or not displayItem() then return false, false end

    local item = displayItem.Item
    if not item or not item() then return false, false end

    local ac = getDisplayItemNumber(item.AC)
    if ac == 0 and item.TotalAC then
        ac = getDisplayItemNumber(item.TotalAC)
    end

    local hp = getDisplayItemNumber(item.HP)
    if hp == 0 and item.HitPoints then
        hp = getDisplayItemNumber(item.HitPoints)
    end

    local mana = getDisplayItemNumber(item.Mana)
    -- Prefer top-level DisplayItem fields for weapon stats, then fallback to Item.*
    local damage = 0
    local delay = 0
    local okDmg, topDamage = pcall(function() return tonumber(displayItem.Damage and displayItem.Damage() or 0) or 0 end)
    local okDly, topDelay = pcall(function() return tonumber(displayItem.ItemDelay and displayItem.ItemDelay() or 0) or 0 end)
    if okDmg and topDamage and topDamage > 0 then damage = topDamage else damage = getDisplayItemNumber(item.Damage) end
    if okDly and topDelay and topDelay > 0 then delay = topDelay else delay = getDisplayItemNumber(item.ItemDelay) end

    target.ac = ac
    target.hp = hp
    target.mana = mana
    target.damage = damage
    target.delay = delay

    -- Optional debug: show what DisplayItem reported for weapon stats
    if db and db._debug then
        printf('[EmuBot][ScanDI] %s: DisplayItem Damage=%d Delay=%d | Item.Damage=%d Item.Delay=%d',
            tostring(target.name or target.slotname or 'item'),
            tonumber(topDamage or 0) or 0,
            tonumber(topDelay or 0) or 0,
            tonumber(getDisplayItemNumber(item.Damage) or 0) or 0,
            tonumber(getDisplayItemNumber(item.ItemDelay) or 0) or 0)
    end

    local hasNonZero = (ac ~= 0) or (hp ~= 0) or (mana ~= 0) or (damage ~= 0) or (delay ~= 0)
    return true, hasNonZero
end

local function getTimeMs()
    if mq.gettime then
        local ok, value = pcall(mq.gettime)
        if ok and value then return value end
    end
    return math.floor((os.clock() or 0) * 1000)
end

local function collectBotNames()
    local set = {}
    local list = {}
    local function tryAdd(name)
        if not name or type(name) ~= 'string' then return end
        local trimmed = name:match('^%s*(.-)%s*$')
        if not trimmed or trimmed == '' then return end
        if bot_inventory and bot_inventory.isBotOwnedByCurrentCharacter and not bot_inventory.isBotOwnedByCurrentCharacter(trimmed) then
            return
        end
        if set[trimmed] then return end
        set[trimmed] = true
        table.insert(list, trimmed)
    end

    if bot_inventory then
        -- Get bots from getAllBots function
        if bot_inventory.getAllBots then
            local allBots = bot_inventory.getAllBots() or {}
            for _, name in ipairs(allBots) do
                tryAdd(name)
            end
        end
        
        -- Get bots from bot_inventories
        if bot_inventory.bot_inventories then
            for name in pairs(bot_inventory.bot_inventories) do
                tryAdd(name)
            end
        end
        
        -- Get bots from cached_bot_list
        if bot_inventory.cached_bot_list then
            for _, name in ipairs(bot_inventory.cached_bot_list) do
                tryAdd(name)
            end
        end
    end
    
    -- Sort the list case-insensitively
    table.sort(list, function(a, b) return (a or ''):lower() < (b or ''):lower() end)

    return list, set
end

local function syncSelectedBotData()
    if not botUI.selectedBot or not botUI.selectedBot.name then return end
    if not bot_inventory or not bot_inventory.bot_inventories then return end
    local botName = botUI.selectedBot.name
    local updated = bot_inventory.bot_inventories[botName]
    if updated then
        local itemCount = updated.equipped and #updated.equipped or 0
        if itemCount > 0 and updated.equipped[1] then
        end
        botUI.selectedBot.data = updated
    end
end

local function collectBotSlotItems(slotId)
    local results = {}
    local names, nameSet = collectBotNames()

    if botUI.selectedBot and botUI.selectedBot.name then
        local name = botUI.selectedBot.name
        local trimmed = name and name:match('^%s*(.-)%s*$') or name
        if trimmed and trimmed ~= '' and not nameSet[trimmed] then
            table.insert(names, trimmed)
            nameSet[trimmed] = true
        end
    end

    if #names == 0 and botUI.selectedBot and botUI.selectedBot.name then
        local trimmed = botUI.selectedBot.name:match('^%s*(.-)%s*$') or botUI.selectedBot.name
        if trimmed and trimmed ~= '' then
            table.insert(names, trimmed)
        end
    end

    for _, botName in ipairs(names) do
        local owned = true
        if bot_inventory and bot_inventory.isBotOwnedByCurrentCharacter then
            owned = bot_inventory.isBotOwnedByCurrentCharacter(botName)
        end
        if owned then
            local foundItem = nil
            local cachedData = bot_inventory and bot_inventory.bot_inventories and bot_inventory.bot_inventories[botName] or nil

            if botUI.selectedBot and botUI.selectedBot.name == botName and botUI.selectedBot.data then
                for _, item in ipairs(botUI.selectedBot.data.equipped or {}) do
                    if tonumber(item.slotid) == slotId then
                        foundItem = item
                        break
                    end
                end
            end

            if not foundItem and cachedData and cachedData.equipped then
                for _, item in ipairs(cachedData.equipped) do
                    if tonumber(item.slotid) == slotId then
                        foundItem = item
                        break
                    end
                end
            end

            table.insert(results, { bot = botName, item = foundItem })

            if not foundItem and bot_inventory and bot_inventory.requestBotInventory then
                botUI._botInventoryLastAttempt[botName] = botUI._botInventoryLastAttempt[botName] or 0
                botUI._botInventoryFetchSet[botName] = botUI._botInventoryFetchSet[botName] or false
                if not botUI._botInventoryFetchSet[botName] then
                    table.insert(botUI._botInventoryFetchQueue, botName)
                    botUI._botInventoryFetchSet[botName] = true
                    if not botUI._botInventoryFetchActive then
                        botUI._botInventoryFetchActive = true
                        enqueueTask(botUI._processBotInventoryQueue)
                    end
                end
            end
        end
    end

    return results
end

local function performDatabasePurge()
    if not db or not db.purge_all then
        return false, 'Database module does not support purge.'
    end

    local ok, err = db.purge_all()
    if not ok then return false, err end

    if bot_inventory then
        bot_inventory.bot_inventories = {}
        bot_inventory.pending_requests = {}
        bot_inventory.current_bot_request = nil
        bot_inventory.cached_bot_list = {}
        bot_inventory.refreshing_bot_list = false
        bot_inventory.bot_list_start_time = nil
        bot_inventory.bot_request_start_time = nil
        bot_inventory.bot_request_phase = 0
        bot_inventory.bot_list_capture_set = {}
        bot_inventory._capture_count = {}
        bot_inventory._itemStatCache = {}
        bot_inventory.initialized = false
        if bot_inventory.init then bot_inventory.init() end
    end

    if bot_groups then
        bot_groups.groups = {}
        if bot_groups.refresh_groups then bot_groups.refresh_groups() end
    end

    botUI.selectedBot = nil
    botUI.selectedBotSlotID = nil
    botUI.selectedBotSlotName = nil
    botUI._itemStatCache = {}
    botUI.lastExportMessage = nil
    botUI.deferred_tasks = {}

    return true
end

function botUI._enqueueBotInventoryFetch(botName)
    if not botName or botName == '' or not bot_inventory or not bot_inventory.requestBotInventory then
        return
    end
    
    -- Check if bot is currently skipped due to failures
    if botUI._skippedBots[botName] then
        local skipTime = botUI._skippedBots[botName]
        local elapsed = os.time() - skipTime
        if elapsed < botUI._failureTimeout then
            printf('[EmuBot] Bot %s is skipped due to failures, %d seconds remaining', botName, botUI._failureTimeout - elapsed)
            return
        else
            -- Reset failure tracking after timeout
            printf('[EmuBot] Failure timeout expired for %s, allowing retry', botName)
            botUI._skippedBots[botName] = nil
            botUI._botFailureCount[botName] = nil
        end
    end
    
    if botUI._botInventoryFetchSet[botName] then return end
    table.insert(botUI._botInventoryFetchQueue, botName)
    botUI._botInventoryFetchSet[botName] = true
    botUI._botInventoryLastAttempt[botName] = 0
    if not botUI._botInventoryFetchActive then
        botUI._botInventoryFetchActive = true
        enqueueTask(botUI._processBotInventoryQueue)
    end
end

function botUI.startScanAllBots()
    if botUI._scanAllActive then
        printf('[EmuBot] Scan All Bots already in progress!')
        return
    end
    
    local botList, _ = collectBotNames()
    if #botList == 0 then
        printf('[EmuBot] No bots found to scan!')
        return
    end
    
    botUI._scanAllActive = true
    botUI._scanAllQueue = {}
    for _, botName in ipairs(botList) do
        table.insert(botUI._scanAllQueue, botName)
    end
    botUI._scanAllBotIndex = 0
    botUI._scanAllCurrentBot = nil
    botUI._scanAllTotalItems = 0
    botUI._scanAllStartTime = os.time()
    botUI._scanAllProgress = string.format('Starting scan of %d bots...', #botList)
    
    printf('[EmuBot] Starting scan of all %d bots...', #botList)
    enqueueTask(botUI._processScanAllBots)
end

-- Begin a scan-all session using the current bot list
function botUI._beginScanAll(campDisabled)
    local botList, _ = collectBotNames()
    if #botList == 0 then
        printf('[EmuBot] No bots found to scan!')
        return true
    end

    botUI._scanAllActive = true
    botUI._scanAllQueue = {}
    for _, botName in ipairs(botList) do
        table.insert(botUI._scanAllQueue, botName)
    end
    botUI._scanAllBotIndex = 0
    botUI._scanAllCurrentBot = nil
    botUI._scanAllTotalItems = 0
    botUI._scanAllStartTime = os.time()
    botUI._scanAllProgress = string.format('Starting scan of %d bots...', #botList)

    botUI.disableCampDuringScanAll = campDisabled and true or false
    if botUI.disableCampDuringScanAll then
        printf('[EmuBot] Starting scan of all %d bots... (camping disabled)', #botList)
    else
        printf('[EmuBot] Starting scan of all %d bots...', #botList)
    end

    enqueueTask(botUI._processScanAllBots)
    return true
end

-- Refresh bot list and then start scan-all once list is ready (or after a short timeout)
function botUI._startScanAllAfterRefresh(campDisabled)
    if bot_inventory and bot_inventory.refreshBotList then
        bot_inventory.refreshBotList()
    end
    local attempts = 0
    local function poll()
        attempts = attempts + 1
        if bot_inventory and bot_inventory.refreshing_bot_list then
            if attempts < 20 then
                enqueueTask(function() mq.delay(250); botUI._startScanAllAfterRefresh_step(campDisabled, attempts) end)
                return true
            end
        end
        botUI._beginScanAll(campDisabled)
        return true
    end
    -- Helper to avoid upvalues being lost in nested enqueueTask closures
    function botUI._startScanAllAfterRefresh_step(campDisabledInner, attemptNum)
        if bot_inventory and bot_inventory.refreshing_bot_list and attemptNum < 20 then
            enqueueTask(function() mq.delay(250); botUI._startScanAllAfterRefresh_step(campDisabledInner, attemptNum + 1) end)
            return true
        end
        botUI._beginScanAll(campDisabledInner)
        return true
    end
    enqueueTask(poll)
    return true
end

function botUI.stopScanAllBots()
    if not botUI._scanAllActive then return end
    
    botUI._scanAllActive = false
    botUI._scanAllQueue = {}
    botUI._scanAllCurrentBot = nil
    botUI._scanAllBotIndex = 0
    botUI._scanAllTotalItems = 0
    botUI._scanAllProgress = 'Scan cancelled'
    
    printf('[EmuBot] Scan All Bots cancelled')
end

function botUI._awaitInventoryForBot(botName, shouldCamp, requestIssued)
    local timeout = 15 -- seconds to wait before giving up on this bot
    local issued = requestIssued ~= false -- default true when nil
    local function poll(startTime)
        -- If scan was cancelled mid-wait, stop
        if not botUI._scanAllActive then return true end

        -- Check if inventory has been captured (primary check)
        local inv = bot_inventory and bot_inventory.getBotInventory and bot_inventory.getBotInventory(botName)
        local requestActive = issued and bot_inventory and bot_inventory.current_bot_request == botName
        if inv and inv.equipped and #inv.equipped > 0 and (not issued or not requestActive) then
            printf('[EmuBot] Inventory captured for %s (%d items). Current request: %s', botName, #inv.equipped, bot_inventory.current_bot_request or 'nil')
            botUI._completeScanAllBotStep(botName, shouldCamp)
            return true
        end

        if issued and not requestActive then
            printf('[EmuBot] Warning: inventory request for %s finished but no new data was detected, continuing with cached data', botName)
            botUI._completeScanAllBotStep(botName, shouldCamp)
            return true
        end

        -- If current_bot_request changed but we don't have inventory yet, that's unexpected
        if issued and bot_inventory.current_bot_request ~= botName and bot_inventory.current_bot_request ~= nil then
            printf('[EmuBot] Warning: bot_inventory moved to %s while waiting for %s (no inventory captured)', bot_inventory.current_bot_request or 'nil', botName)
            -- Give it a moment to see if inventory appears
            local elapsed = os.time() - startTime
            if elapsed > 8 then  -- If we've been waiting a while, give up
                printf('[EmuBot] Giving up on %s after %d seconds with no inventory', botName, elapsed)
                botUI._completeScanAllBotStep(botName, shouldCamp)
                return true
            end
        end

        -- Timeout check
        if os.time() - startTime >= timeout then
            printf('[EmuBot] Timeout waiting for inventory from %s; proceeding.', botName)
            -- Only clear on timeout if it's still our request
            if issued and bot_inventory.current_bot_request == botName then
                printf('[EmuBot] Clearing stale bot_inventory request for %s due to timeout', botName)
                bot_inventory.current_bot_request = nil
                bot_inventory.bot_request_start_time = nil
                bot_inventory.bot_request_phase = 0
            end
            botUI._completeScanAllBotStep(botName, shouldCamp)
            return true
        end

        -- Update UI text while waiting
        botUI._scanAllProgress = string.format('Waiting on %s inventory...', botName)
        -- Re-enqueue poll after a short delay to avoid blocking, preserving original startTime
        enqueueTask(function()
            mq.delay(300) -- Back to faster polling to catch inventory quickly
            poll(startTime)
        end)
        return true
    end
    enqueueTask(function() poll(os.time()) end)
end

function botUI._processScanAllBots()
    if not botUI._scanAllActive then return true end
    
    -- Check if we're done
    if #botUI._scanAllQueue == 0 then
        botUI._scanAllActive = false
        local itemQueueSize = #botUI._scanQueue
        botUI._scanAllProgress = string.format('Scan complete! Processed %d bots, %d items queued for scanning', 
            botUI._scanAllBotIndex, botUI._scanAllTotalItems)
        printf('[EmuBot] Scan All Bots completed! Processed %d bots, queued %d items for detailed scanning', 
            botUI._scanAllBotIndex, botUI._scanAllTotalItems)
        if bot_inventory and bot_inventory.bot_inventories then
            for botName, data in pairs(bot_inventory.bot_inventories) do
                local itemCount = data.equipped and #data.equipped or 0
                local firstItem = (data.equipped and data.equipped[1] and data.equipped[1].name) or 'None'
            end
        end
        
        if itemQueueSize > 0 then
            printf('[EmuBot] %d items are still being scanned in the background...', itemQueueSize)
        end
        
        -- Restore original camp setting after scan is complete
        botUI.disableCampDuringScanAll = botUI._originalCampSetting
        
        return true
    end
    
    -- Get the next bot to process
    local currentBot = botUI._scanAllQueue[1]
    if not currentBot then
        enqueueTask(botUI._processScanAllBots)
        return true
    end
    
    botUI._scanAllCurrentBot = currentBot
    botUI._scanAllBotIndex = botUI._scanAllBotIndex + 1
    botUI._scanAllProgress = string.format('Processing bot %d/%d: %s', 
        botUI._scanAllBotIndex, 
        botUI._scanAllBotIndex + #botUI._scanAllQueue - 1, 
        currentBot)
    
    -- Check if bot is already spawned
    local botSpawn = mq.TLO.Spawn(string.format('= %s', currentBot))
    local isSpawned = botSpawn and botSpawn.ID and botSpawn.ID() and botSpawn.ID() > 0
    
    -- Safety check: ensure no other bot request is active
    if bot_inventory.current_bot_request and bot_inventory.current_bot_request ~= currentBot then
        -- Check if the old request is actually stale (started more than 20 seconds ago)
        local requestAge = bot_inventory.bot_request_start_time and (os.time() - bot_inventory.bot_request_start_time) or 999
        if requestAge > 20 then
            printf('[EmuBot] Clearing stale bot request (%s, %d seconds old) before starting %s', bot_inventory.current_bot_request, requestAge, currentBot)
            bot_inventory.current_bot_request = nil
            bot_inventory.bot_request_start_time = nil
            bot_inventory.bot_request_phase = 0
        else
            printf('[EmuBot] Warning: Recent bot request (%s) still active, but proceeding with %s', bot_inventory.current_bot_request, currentBot)
        end
    end

    -- Determine if we should camp based on the setting
    local shouldCamp = not botUI.disableCampDuringScanAll
    
    if isSpawned then
        -- Bot is already spawned, just get inventory
        printf('[EmuBot] Bot %s already spawned, requesting inventory...', currentBot)
        local requestStarted = bot_inventory.requestBotInventory(currentBot)
        if shouldCamp then
            printf('[EmuBot] Will camp %s after inventory capture', currentBot)
        else
            printf('[EmuBot] Camping disabled - will leave %s spawned', currentBot)
        end
        botUI._awaitInventoryForBot(currentBot, shouldCamp, requestStarted)
    else
        -- Bot needs to be spawned
        printf('[EmuBot] Spawning bot %s...', currentBot)
        mq.cmdf('/say ^spawn %s', currentBot)

        enqueueTask(function()
            mq.delay(3000) -- Wait for spawn to appear
            local spawnCheck = mq.TLO.Spawn(string.format('= %s', currentBot))
            if spawnCheck and spawnCheck.ID and spawnCheck.ID() and spawnCheck.ID() > 0 then
                printf('[EmuBot] Bot %s spawned, requesting inventory...', currentBot)
                local requestStarted = bot_inventory.requestBotInventory(currentBot)
                if shouldCamp then
                    printf('[EmuBot] Will camp %s after inventory capture', currentBot)
                else
                    printf('[EmuBot] Camping disabled - will leave %s spawned', currentBot)
                end
                botUI._awaitInventoryForBot(currentBot, shouldCamp, requestStarted)
            else
                printf('[EmuBot] Failed to spawn bot %s, skipping...', currentBot)
                botUI._completeScanAllBotStep(currentBot, false)
            end
        end)
    end
    
    return true
end

local function _targetBotByName(botName)
    if not botName or botName == '' then return false end
    local spawn = mq.TLO.Spawn(string.format('= %s', botName))
    if spawn and spawn.ID and spawn.ID() and spawn.ID() > 0 then
        mq.cmdf('/target id %d', spawn.ID())
        mq.delay(200)
    else
        mq.cmdf('/target "%s"', botName)
        mq.delay(200)
    end
    local tgt = mq.TLO.Target
    return (tgt and tgt() and tgt.Name() == botName) or false
end

function botUI._completeScanAllBotStep(botName, shouldCamp)
    -- Get the bot's inventory data and queue items for scanning
    local botData = bot_inventory and bot_inventory.getBotInventory and bot_inventory.getBotInventory(botName)
    if botData and botData.equipped then
        local itemsToScan = {}
        for _, item in ipairs(botData.equipped) do
            local scanReasons = {}
            local sid = tonumber(item.slotid or -1) or -1
            local slotNameLower = tostring(item.slotname or item.slot or ''):lower()
            local isAmmoSlot = (slotNameLower == 'ammo') or (sid == 21)

            if not isAmmoSlot then
                -- Primary stats missing or zero?
                local hasPrimaryStats = (item.ac ~= nil) or (item.hp ~= nil) or (item.mana ~= nil)
                local acVal = tonumber(item.ac or 0) or 0
                local hpVal = tonumber(item.hp or 0) or 0
                local manaVal = tonumber(item.mana or 0) or 0

                if not hasPrimaryStats then
                    table.insert(scanReasons, 'missing AC/HP/Mana')
                elseif acVal == 0 and hpVal == 0 and manaVal == 0 then
                    table.insert(scanReasons, 'AC/HP/Mana all zero')
                end
            end

            -- Weapon stats check removed (primary weapons without damage/delay are no longer forced to rescan)
            
            if #scanReasons > 0 then
                local itemName = item.name or 'Unknown Item'
                local slotLabel = item.slotname or item.slot or item.slotid or '?'
                local reasonText = table.concat(scanReasons, '; ')
                if item.itemlink and item.itemlink ~= '' then
                    printf('[EmuBot]   -> %s [%s] queued for rescan (%s). Stats: AC=%s HP=%s Mana=%s DMG=%s DLY=%s',
                        itemName,
                        tostring(slotLabel),
                        reasonText,
                        tostring(item.ac or 'nil'),
                        tostring(item.hp or 'nil'),
                        tostring(item.mana or 'nil'),
                        tostring(item.damage or 'nil'),
                        tostring(item.delay or 'nil')
                    )
                    table.insert(itemsToScan, item)
                else
                    printf('[EmuBot]   -> %s [%s] needs rescan (%s) but has no item link available',
                        itemName,
                        tostring(slotLabel),
                        reasonText
                    )
                end
            end
        end
        
        if #itemsToScan > 0 then
            botUI._scanAllTotalItems = botUI._scanAllTotalItems + #itemsToScan
            printf('[EmuBot] Queueing %d items from %s for detailed scanning...', #itemsToScan, botName)
            for _, item in ipairs(itemsToScan) do
                botUI.enqueueItemScan(item, botName)
            end
        else
            printf('[EmuBot] Bot %s inventory complete, no items need scanning', botName)
        end
    else
        printf('[EmuBot] Warning: No inventory data found for %s after scan attempt', botName)
    end

    -- Camp bot if requested, otherwise proceed immediately
    if shouldCamp then
        printf('[EmuBot] Camping bot %s...', botName)
        local targeted = _targetBotByName(botName)
        if targeted then
            mq.cmd('/say ^botcamp')
        else
            printf('[EmuBot] Warning: could not target %s for camp. Skipping camp command.', botName)
        end

        -- Wait for the bot to despawn before proceeding (timeout safety)
        local startWait = os.time()
        local timeout = 10 -- seconds
        local function waitDespawn()
            local spawned = mq.TLO.Spawn(string.format('= %s', botName))
            local stillThere = spawned and spawned.ID and spawned.ID() and spawned.ID() > 0
            if not stillThere then
                -- Remove this bot from the queue and proceed
                if botUI._scanAllQueue[1] == botName then
                    table.remove(botUI._scanAllQueue, 1)
                end
                enqueueTask(botUI._processScanAllBots)
                return true
            end
            if os.time() - startWait >= timeout then
                printf('[EmuBot] Timed out waiting for %s to camp. Continuing...', botName)
                if botUI._scanAllQueue[1] == botName then
                    table.remove(botUI._scanAllQueue, 1)
                end
                enqueueTask(botUI._processScanAllBots)
                return true
            end
            botUI._scanAllProgress = string.format('Waiting for %s to camp...', botName)
            enqueueTask(function()
                mq.delay(500)
                waitDespawn()
            end)
            return true
        end
        enqueueTask(function()
            mq.delay(500)
            waitDespawn()
        end)
    else
        printf('[EmuBot] Leaving bot %s spawned (camping disabled)', botName)
        -- Proceed immediately without camping
        if botUI._scanAllQueue[1] == botName then
            table.remove(botUI._scanAllQueue, 1)
        end
        enqueueTask(botUI._processScanAllBots)
    end
end

function botUI._processBotInventoryQueue()
    local queue = botUI._botInventoryFetchQueue
    if not queue or #queue == 0 then
        botUI._botInventoryFetchActive = false
        return true
    end

    local botName = queue[1]
    if not botName then
        table.remove(queue, 1)
        return botUI._processBotInventoryQueue()
    end
    
    -- Check if bot is skipped due to failures
    if botUI._skippedBots[botName] then
        -- Remove from queue and skip processing
        table.remove(queue, 1)
        botUI._botInventoryFetchSet[botName] = nil
        enqueueTask(botUI._processBotInventoryQueue)
        return true
    end

    if bot_inventory.current_bot_request and bot_inventory.current_bot_request ~= ''
        and bot_inventory.current_bot_request ~= botName then
        enqueueTask(botUI._processBotInventoryQueue)
        return true
    end

    local data = bot_inventory.bot_inventories and bot_inventory.bot_inventories[botName]
    if data and data.equipped and #data.equipped > 0 then
        -- Success - reset failure count and remove from queue
        table.remove(queue, 1)
        botUI._botInventoryFetchSet[botName] = nil
        botUI._botInventoryLastAttempt[botName] = nil
        botUI._botFailureCount[botName] = nil
        enqueueTask(botUI._processBotInventoryQueue)
        return true
    end
    
    -- Check if bot inventory system indicates failure
    if not bot_inventory.current_bot_request and botUI._botInventoryLastAttempt[botName] then
        local lastAttemptTime = botUI._botInventoryLastAttempt[botName]
        local now = getTimeMs()
        local timeSinceAttempt = now - lastAttemptTime
        
        -- If more than 15 seconds since last attempt and no current request, it likely failed
        if timeSinceAttempt > 15000 then -- 15 seconds
            local failCount = (botUI._botFailureCount[botName] or 0) + 1
            botUI._botFailureCount[botName] = failCount
            
            printf('[EmuBot] Bot %s inventory request appears to have failed (attempt %d/%d)', botName, failCount, botUI._maxFailures)
            
            if failCount >= botUI._maxFailures then
                -- Skip this bot
                printf('[EmuBot] Bot %s exceeded max failures, skipping for %d seconds', botName, botUI._failureTimeout)
                botUI._skippedBots[botName] = os.time()
                table.remove(queue, 1)
                botUI._botInventoryFetchSet[botName] = nil
                enqueueTask(botUI._processBotInventoryQueue)
                return true
            end
        end
    end

    local delayMs = math.max(100, math.floor((botUI.botFetchDelay or 1.0) * 1000))
    local now = getTimeMs()
    local lastAttempt = botUI._botInventoryLastAttempt[botName] or 0
    if now - lastAttempt >= delayMs then
        botUI._botInventoryLastAttempt[botName] = now
        
        -- Check failure count before attempting
        local failCount = botUI._botFailureCount[botName] or 0
        if failCount < botUI._maxFailures then
            local success = bot_inventory.requestBotInventory(botName)
            if not success then
                -- Request was rejected (likely due to skip check)
                printf('[EmuBot] Request rejected for %s, removing from queue', botName)
                table.remove(queue, 1)
                botUI._botInventoryFetchSet[botName] = nil
                enqueueTask(botUI._processBotInventoryQueue)
                return true
            end
        else
            printf('[EmuBot] Bot %s has too many failures, removing from queue', botName)
            table.remove(queue, 1)
            botUI._botInventoryFetchSet[botName] = nil
            enqueueTask(botUI._processBotInventoryQueue)
            return true
        end
    end

    enqueueTask(botUI._processBotInventoryQueue)
    return true
end

local function persistItemStatsForBot(item, botName)
    if not item then return botName end
    local resolvedBot = botName
    if not resolvedBot then
        for name, inv in pairs(bot_inventory.bot_inventories or {}) do
            for _, it in ipairs(inv.equipped or {}) do
                if it == item then
                    resolvedBot = name
                    break
                end
            end
            if resolvedBot then break end
        end
    end
    if resolvedBot then
        local data = bot_inventory.getBotInventory and bot_inventory.getBotInventory(resolvedBot)
        if data then
            local meta = bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[resolvedBot] or nil
            db.save_bot_inventory(resolvedBot, data, meta)
        end
    end
    return resolvedBot
end

function botUI._processNextScan()
    local entry = table.remove(botUI._scanQueue, 1)
    if not entry then
        botUI._scanActive = false
        return true
    end
    local current = entry.item
    local currentBot = entry.bot
    local itemID = tonumber(current and current.itemID or 0) or 0

    if itemID > 0 then
        local cached = botUI._itemStatCache[itemID]
        if cached then
            current.ac = tonumber(cached.ac or current.ac or 0) or 0
            current.hp = tonumber(cached.hp or current.hp or 0) or 0
            current.mana = tonumber(cached.mana or current.mana or 0) or 0
            current.damage = tonumber(cached.damage or current.damage or 0) or 0
            current.delay = tonumber(cached.delay or current.delay or 0) or 0
            local cachedIcon = tonumber(cached.icon or 0) or 0
            if cachedIcon > 0 then
                current.icon = cachedIcon
                current.iconID = cachedIcon
            end
            currentBot = persistItemStatsForBot(current, currentBot)
            enqueueTask(botUI._processNextScan)
            return true
        end
    end

    current.ac = 0
    current.hp = 0
    current.mana = 0
    current.damage = 0
    current.delay = 0
    local links = mq.ExtractLinks(current.itemlink or '')
    -- If no link stored for this item, refresh ^invlist for the owning bot to capture links from chat, then retry
    if (not links or #links == 0) then
        if currentBot and bot_inventory and bot_inventory.requestBotInventory then
            local retries = 0
            local maxRetries = 3
            local function fetchLinksFromBot()
                retries = retries + 1
                bot_inventory.requestBotInventory(currentBot)
                mq.delay(700)
                local updated = bot_inventory.getBotInventory and bot_inventory.getBotInventory(currentBot)
                if updated and updated.equipped then
                    local found
                    for _, it in ipairs(updated.equipped) do
                        if tonumber(it.slotid or -1) == tonumber(current.slotid or -2) then
                            found = it
                            break
                        end
                    end
                    if found and found.itemlink and found.itemlink ~= '' then
                        current.itemlink = found.itemlink
                        local l = mq.ExtractLinks(current.itemlink or '')
                        if l and #l > 0 then
                            links = l
                            -- Proceed with this same scan now that we have links
                            enqueueTask(botUI._processNextScan)
                            return true
                        end
                    end
                end
                if retries < maxRetries then
                    enqueueTask(fetchLinksFromBot)
                else
                    -- Give up on this item; move on
                    enqueueTask(botUI._processNextScan)
                end
                return true
            end
            enqueueTask(fetchLinksFromBot)
            return true
        else
            enqueueTask(botUI._processNextScan)
            return true
        end
    end
    local link = links[1]
    local wnd = mq.TLO.Window('ItemDisplayWindow')
    if wnd() and wnd.Open() then wnd.DoClose() end
    if mq.ExecuteTextLink then mq.ExecuteTextLink(link) end
    local attempts = 0
    local maxAttempts = 20

    local function tryRead()
        local w = mq.TLO.Window('ItemDisplayWindow')
        if not w() or not w.Open() then return false, false, false, false end

        captureDisplayItemIcon(current)
        local hasIcon = tonumber(current.icon or current.iconID or 0) or 0
        hasIcon = hasIcon > 0
        local augCaptured = captureAugmentData(current)
        local statsCaptured, hasNonZero = populateStatsFromDisplayItem(current)

        -- Do not supplement from Item TLO here; rely on DisplayItem for scan results

        return statsCaptured, hasIcon, augCaptured, hasNonZero
    end

    local function poll()
        attempts = attempts + 1
        local statsCaptured, hasIcon, augCaptured, hasNonZero = tryRead()
        local hasWeaponStats = (tonumber(current.damage or 0) > 0) or (tonumber(current.delay or 0) > 0)
        if statsCaptured and (hasIcon or hasNonZero or hasWeaponStats) then
            local w = mq.TLO.Window('ItemDisplayWindow')
            if w() and w.Open() then w.DoClose() end

            if itemID > 0 then
                botUI._itemStatCache[itemID] = {
                    ac = tonumber(current.ac or 0) or 0,
                    hp = tonumber(current.hp or 0) or 0,
                    mana = tonumber(current.mana or 0) or 0,
                    damage = tonumber(current.damage or 0) or 0,
                    delay = tonumber(current.delay or 0) or 0,
                    icon = tonumber(current.icon or current.iconID or 0) or 0,
                }
            end

            currentBot = persistItemStatsForBot(current, currentBot)

            enqueueTask(botUI._processNextScan)
            return true
        end

        if attempts >= maxAttempts then
            local w = mq.TLO.Window('ItemDisplayWindow')
            if not hasIcon then
                captureDisplayItemIcon(current)
                hasIcon = tonumber(current.icon or current.iconID or 0) > 0
            end
            if not augCaptured then
                augCaptured = captureAugmentData(current)
            end
            if w() and w.Open() then w.DoClose() end
            if not statsCaptured then
                printf('[EmuBot] Warning: scan timed out for %s', tostring(current.name or current.slotname or 'unknown item'))
            elseif not hasIcon then
                printf('[EmuBot] Warning: icon not captured for %s', tostring(current.name or current.slotname or 'unknown item'))
            elseif not hasNonZero then
                -- No stats found, but we at least reset them to zero for consistency.
            end
            local hasUsefulStats = (tonumber(current.ac or 0) > 0) or (tonumber(current.hp or 0) > 0)
                or (tonumber(current.mana or 0) > 0) or (tonumber(current.damage or 0) > 0)
                or (tonumber(current.delay or 0) > 0)
            if itemID > 0 and hasUsefulStats then
                botUI._itemStatCache[itemID] = {
                    ac = tonumber(current.ac or 0) or 0,
                    hp = tonumber(current.hp or 0) or 0,
                    mana = tonumber(current.mana or 0) or 0,
                    damage = tonumber(current.damage or 0) or 0,
                    delay = tonumber(current.delay or 0) or 0,
                    icon = tonumber(current.icon or current.iconID or 0) or 0,
                }
            end
            if hasUsefulStats then
                currentBot = persistItemStatsForBot(current, currentBot)
            end
            enqueueTask(botUI._processNextScan)
            return true
        end

        enqueueTask(poll)
        return true
    end

    enqueueTask(poll)
    return true
end

function botUI.enqueueItemScan(item, botName)
    if not item or not item.itemlink then return end
    table.insert(botUI._scanQueue, { item = item, bot = botName })
    if botUI._scanActive then return end
    botUI._scanActive = true
    enqueueTask(botUI._processNextScan)
end

-- Function to manually skip a bot
function botUI.skipBot(botName, reason)
    if not botName or botName == '' then return false end
    botUI._skippedBots[botName] = os.time()
    botUI._botFailureCount[botName] = botUI._maxFailures
    
    -- Remove from current queues
    for i = #botUI._botInventoryFetchQueue, 1, -1 do
        if botUI._botInventoryFetchQueue[i] == botName then
            table.remove(botUI._botInventoryFetchQueue, i)
        end
    end
    botUI._botInventoryFetchSet[botName] = nil
    
    printf('[EmuBot] Manually skipped bot %s%s', botName, reason and (' - ' .. reason) or '')
    return true
end

-- Function to clear a bot from skip list
function botUI.unskipBot(botName)
    if not botName or botName == '' then return false end
    
    local wasSkipped = botUI._skippedBots[botName] ~= nil
    botUI._skippedBots[botName] = nil
    botUI._botFailureCount[botName] = nil
    
    if wasSkipped then
        printf('[EmuBot] Removed %s from skip list', botName)
    else
        printf('[EmuBot] Bot %s was not in skip list', botName)
    end
    return wasSkipped
end

-- Function to clear all skipped bots
function botUI.clearAllSkippedBots()
    local count = 0
    for botName, _ in pairs(botUI._skippedBots) do
        count = count + 1
    end
    
    botUI._skippedBots = {}
    botUI._botFailureCount = {}
    
    printf('[EmuBot] Cleared %d bots from skip list', count)
    return count
end

-- Function to get list of skipped bots
function botUI.getSkippedBots()
    local skipped = {}
    local now = os.time()
    
    for botName, skipTime in pairs(botUI._skippedBots) do
        local elapsed = now - skipTime
        local remaining = math.max(0, botUI._failureTimeout - elapsed)
        table.insert(skipped, {
            name = botName,
            skipTime = skipTime,
            remaining = remaining,
            failures = botUI._botFailureCount[botName] or 0
        })
    end
    
    -- Sort by time remaining
    table.sort(skipped, function(a, b) return a.remaining > b.remaining end)
    
    return skipped
end

local function getSlotNameFromID(slotID)
    local slotNames = {
        [0] = 'Charm',
        [1] = 'Left Ear',
        [2] = 'Head',
        [3] = 'Face',
        [4] = 'Right Ear',
        [5] = 'Neck',
        [6] = 'Shoulders',
        [7] = 'Arms',
        [8] = 'Back',
        [9] = 'Left Wrist',
        [10] = 'Right Wrist',
        [11] = 'Range',
        [12] = 'Hands',
        [13] = 'Primary',
        [14] = 'Secondary',
        [15] = 'Left Ring',
        [16] = 'Right Ring',
        [17] = 'Chest',
        [18] = 'Legs',
        [19] = 'Feet',
        [20] = 'Waist',
        [21] = 'Power Source',
        [22] = 'Ammo',
    }
    return slotNames[slotID] or 'Unknown Slot'
end

local function getEquippedSlotLayout()
    return {
        {1, 2, 3, 4},
        {17, '', '', 5},
        {7, '', '', 8},
        {20, '', '', 6},
        {9, '', '', 10},
        {18, 12, 0, 19},
        {'', 15, 16, 21},
        {13, 14, 11, 22},
    }
end

local function getSlotName(slotId)
    return getSlotNameFromID(slotId) or 'Unknown'
end

-- Function to check if an item can be worn in a specific slot
local function canItemFitInSlot(itemTLO, slotId)
    if not itemTLO or not itemTLO() then return false end
    
    -- Get target slot ID as number for comparison
    local targetSlotId = tonumber(slotId)
    if not targetSlotId then return false end
    
    -- Get number of worn slots for this item
    local slotCount = 0
    local success, count = pcall(function() return itemTLO.WornSlots() end)
    if success and count then slotCount = tonumber(count) or 0 end
    
    if slotCount == 0 then return false end
    
    -- Check each worn slot by ID number instead of name
    for i = 1, slotCount do
        local success, slotIdValue = pcall(function() return itemTLO.WornSlot(i).ID() end)
        if success and slotIdValue and tonumber(slotIdValue) == targetSlotId then
            return true
        end
    end
    
    return false
end

-- Alternative function to check by name if ID method doesn't work
local function canItemFitInSlotByName(itemTLO, slotId)
    if not itemTLO or not itemTLO() then return false end
    
    -- Convert from slotId to slot name for comparison
    local targetSlotName = getSlotNameFromID(tonumber(slotId))
    if not targetSlotName then return false end
    
    -- Get number of worn slots for this item
    local slotCount = 0
    local success, count = pcall(function() return itemTLO.WornSlots() end)
    if success and count then slotCount = tonumber(count) or 0 end
    
    if slotCount == 0 then return false end
    
    -- Check each worn slot by name
    for i = 1, slotCount do
        local success, slotName = pcall(function() return itemTLO.WornSlot(i)() end)
        if success and slotName and slotName == targetSlotName then
            return true
        end
    end
    
    return false
end

-- Function to check if an item can be used by a specific class
local function canItemBeUsedByClass(itemTLO, className)
    if not itemTLO or not itemTLO() or not className then return false end
    
    -- Get number of classes that can use this item
    local classCount = 0
    local success, count = pcall(function() return itemTLO.Classes() end)
    if success and count then classCount = tonumber(count) or 0 end
    
    if classCount == 0 then return false end
    
    -- If item has 16 classes, it's usable by all classes
    if classCount >= 16 then
        return true
    end
    
    -- Check each class this item can be used by
    for i = 1, classCount do
        local success, itemClass = pcall(function() return itemTLO.Class(i)() end)
        if success and itemClass then
            -- Handle different class name formats
            local normalizedItemClass = itemClass:upper()
            local normalizedBotClass = className:upper()
            
            -- Direct match
            if normalizedItemClass == normalizedBotClass then
                return true
            end
            
            -- Handle common abbreviations and variations
            local classMap = {
                ["WAR"] = "WARRIOR",
                ["CLR"] = "CLERIC", 
                ["PAL"] = "PALADIN",
                ["RNG"] = "RANGER",
                ["SHD"] = "SHADOWKNIGHT", ["SK"] = "SHADOWKNIGHT", ["SHADOWKNIGHT"] = "SHADOWKNIGHT",
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
                ["BER"] = "BERSERKER"
            }
            
            -- Try mapped versions
            local mappedItemClass = classMap[normalizedItemClass] or normalizedItemClass
            local mappedBotClass = classMap[normalizedBotClass] or normalizedBotClass
            
            if mappedItemClass == mappedBotClass then
                return true
            end
            
            -- Try reverse mapping
            if classMap[mappedBotClass] == normalizedItemClass or 
               classMap[mappedItemClass] == normalizedBotClass then
                return true
            end
        end
    end
    
    return false
end

-- Function to get bot class information
local function getBotClass(botName)
    if not botName then return nil end
    
    -- First check the bot list capture data
    if bot_inventory and bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[botName] then
        return bot_inventory.bot_list_capture_set[botName].Class
    end
    
    -- Fallback: try to get from live spawn if present
    local ok, className = pcall(function()
        local s = mq.TLO.Spawn(string.format('= %s', botName))
        return s and s.Class and s.Class() or nil
    end)
    if ok and className and className ~= '' then return className end

    -- If not found, try to get from cached bot list or other sources
    -- This is a fallback - you might need to adapt based on your data structure
    return nil
end

-- Function to create an item data structure from a MQ item TLO
local function createItemDataFromTLO(itemTLO, location, slotid, bagid, slotname)
    if not itemTLO or not itemTLO() then return nil end
    
    local item = {
        name = itemTLO.Name() or "Unknown Item",
        slotid = slotid,
        slotname = slotname or "",
        itemlink = itemTLO.ItemLink("CLICKABLE")() or "",
        icon = tonumber(itemTLO.Icon() or 0) or 0,
        iconID = tonumber(itemTLO.Icon() or 0) or 0,
        ac = tonumber(itemTLO.AC() or 0) or 0,
        hp = tonumber(itemTLO.HP() or 0) or 0,
        mana = tonumber(itemTLO.Mana() or 0) or 0,
        itemID = tonumber(itemTLO.ID() or 0) or 0,
        location = location,
        bagid = bagid,
        nodrop = itemTLO.NoDrop() and 1 or 0,
    }
    
    -- Optional: if you want to gather augments too
    for augSlot = 1, 6 do
        local augItem = itemTLO.AugSlot(augSlot).Item
        if augItem() then
            item["aug" .. augSlot .. "Name"] = augItem.Name()
            item["aug" .. augSlot .. "link"] = augItem.ItemLink("CLICKABLE")()
            item["aug" .. augSlot .. "Icon"] = augItem.Icon()
        end
    end
    
    return item
end

-- Function to scan local character inventory
function botUI.scanLocalInventory(forceRefresh)
    -- Check cache validity
    local now = os.time()
    if not forceRefresh and 
       botUI.localInventoryCache and 
       (now - botUI.localInventoryCacheTime) < botUI.localInventoryCacheDuration then
        return botUI.localInventoryCache
    end
    
    local result = {
        equipped = {},
        bags = {}
    }
    
    -- Scan equipped items
    for slot = 0, 22 do
        local item = mq.TLO.Me.Inventory(slot)
        if item() then
            local slotName = getSlotName(slot)
            local itemData = createItemDataFromTLO(item, "Equipped", slot, nil, slotName)
            if itemData then
                table.insert(result.equipped, itemData)
            end
        end
    end
    
    -- Scan general inventory and bags
    for invSlot = 23, 34 do
        local pack = mq.TLO.Me.Inventory(invSlot)
        if pack() and pack.Container() > 0 then
            local bagid = invSlot - 22  -- Convert to 1-based bag index
            result.bags[bagid] = {}
            
            for slot = 1, pack.Container() do
                local item = pack.Item(slot)
                if item() then
                    local itemData = createItemDataFromTLO(item, "Bags", slot, bagid, pack.Name() or "")
                    if itemData then
                        table.insert(result.bags[bagid], itemData)
                    end
                end
            end
        end
    end
    
    -- Update cache
    botUI.localInventoryCache = result
    botUI.localInventoryCacheTime = now
    
    return result
end

-- Debug function to test slot compatibility for a specific item
function botUI.debugItemSlotCompatibility(itemName, slotId, className)
    local item = mq.TLO.FindItem(itemName)
    if not item() then
        printf('[EmuBot] Item "%s" not found', itemName)
        return
    end
    
    printf('[EmuBot] Testing compatibility for "%s" with slot %s (ID: %d)', itemName, getSlotNameFromID(slotId) or 'Unknown', slotId)
    if className then
        printf('[EmuBot] Testing class compatibility with: %s', className)
    end
    printf('[EmuBot] Item Type: %s', item.Type() or 'Unknown')
    printf('[EmuBot] Item Class: %s', item.ItemClass() or 'Unknown')
    
    local slotCount = 0
    local success, count = pcall(function() return item.WornSlots() end)
    if success and count then slotCount = tonumber(count) or 0 end
    
    printf('[EmuBot] Item has %d worn slot(s):', slotCount)
    
    for i = 1, slotCount do
        local success1, slotIdValue = pcall(function() return item.WornSlot(i).ID() end)
        local success2, slotName = pcall(function() return item.WornSlot(i)() end)
        
        local slotIdStr = success1 and slotIdValue and tostring(slotIdValue) or 'N/A'
        local slotNameStr = success2 and slotName or 'N/A'
        
        printf('[EmuBot]   Slot %d: ID=%s, Name="%s", Matches=%s', i, slotIdStr, slotNameStr, 
               (success1 and tonumber(slotIdValue) == tonumber(slotId)) and 'YES' or 'NO')
    end
    
    local fits1 = canItemFitInSlot(item, slotId)
    local fits2 = canItemFitInSlotByName(item, slotId)
    
    printf('[EmuBot] Slot compatibility: ID method=%s, Name method=%s', 
           fits1 and 'YES' or 'NO', fits2 and 'YES' or 'NO')
    
    -- Test class compatibility if class provided
    if className then
        printf('[EmuBot] Class compatibility testing:')
        local classCount = 0
        local success, count = pcall(function() return item.Classes() end)
        if success and count then classCount = tonumber(count) or 0 end
        
        printf('[EmuBot] Item usable by %d class(es):', classCount)
        
        for i = 1, classCount do
            local success, itemClass = pcall(function() return item.Class(i)() end)
            if success and itemClass then
                printf('[EmuBot]   Class %d: %s', i, itemClass)
            end
        end
        
        local classCompatible = canItemBeUsedByClass(item, className)
        printf('[EmuBot] Class compatibility result: %s', classCompatible and 'YES' or 'NO')
        
        local overallCompatible = (fits1 or fits2) and classCompatible
        printf('[EmuBot] Overall compatibility: %s', overallCompatible and 'YES' or 'NO')
    end
end

-- Function to find items in local inventory that can fit in a specific slot
function botUI.findLocalItemsForSlot(slotId, compareItem, botName)
    local localInventory = botUI.scanLocalInventory()
    local compatibleItems = {}
    
    -- Get bot class for filtering
    local botClass = nil
    if botName then
        botClass = getBotClass(botName)
    end
    
    printf('[EmuBot] Scanning local inventory for slot %s (ID: %d)', getSlotNameFromID(slotId) or 'Unknown', slotId)
    if botClass then
        printf('[EmuBot] Filtering for bot class: %s', botClass)
    else
        printf('[EmuBot] No class filtering (bot class unknown)')
    end
    printf('[EmuBot] Found %d equipped items and %d bags to scan', #localInventory.equipped, 
           (function() local count = 0; for _ in pairs(localInventory.bags) do count = count + 1 end; return count end)())
    
    -- Check equipped items
    for _, item in ipairs(localInventory.equipped) do
        local itemTLO = mq.TLO.Me.Inventory(item.slotid)
        if itemTLO() then
            printf('[EmuBot] Testing equipped item: %s (slot %d)', item.name, item.slotid)
            local fits = canItemFitInSlot(itemTLO, slotId)
            if not fits then
                -- Try backup method
                fits = canItemFitInSlotByName(itemTLO, slotId)
            end
            
            local classCompatible = true
            if botClass then
                classCompatible = canItemBeUsedByClass(itemTLO, botClass)
                if not classCompatible then
                    printf('[EmuBot] ✗ Equipped item %s slot-compatible but wrong class', item.name)
                end
            end
            
            if fits and classCompatible then
                printf('[EmuBot] ✓ Found compatible equipped item: %s', item.name)
                -- Create a copy to avoid modifying original
                local compatibleItem = {}
                for k, v in pairs(item) do
                    compatibleItem[k] = v
                end
                compatibleItem.source = "equipped"
                compatibleItem.classCompatible = classCompatible
                table.insert(compatibleItems, compatibleItem)
            else
                local reason = not fits and 'slot incompatible' or 'class incompatible'
                printf('[EmuBot] ✗ Equipped item %s not compatible (%s)', item.name, reason)
            end
        else
            printf('[EmuBot] ⚠ Could not access equipped item TLO for slot %d', item.slotid)
        end
    end
    
    -- Check bag items
    for bagid, bag in pairs(localInventory.bags) do
        printf('[EmuBot] Scanning bag %d with %d items', bagid, #bag)
        for _, item in ipairs(bag) do
            local invSlot = bagid + 22  -- Convert to actual inventory slot
            local pack = mq.TLO.Me.Inventory(invSlot)
            if pack() and pack.Container() > 0 then
                local itemTLO = pack.Item(item.slotid)
                if itemTLO() then
                    printf('[EmuBot] Testing bag item: %s (bag %d, slot %d)', item.name, bagid, item.slotid)
                    local fits = canItemFitInSlot(itemTLO, slotId)
                    if not fits then
                        -- Try backup method
                        fits = canItemFitInSlotByName(itemTLO, slotId)
                    end
                    
                    local classCompatible = true
                    if botClass then
                        classCompatible = canItemBeUsedByClass(itemTLO, botClass)
                    end
                    
                    if fits and classCompatible then
                        local compatibleItem = {}
                        for k, v in pairs(item) do
                            compatibleItem[k] = v
                        end
                        compatibleItem.source = "bag"
                        compatibleItem.sourceBag = bagid
                        compatibleItem.classCompatible = classCompatible
                        table.insert(compatibleItems, compatibleItem)
                    else
                        local reason = not fits and 'slot incompatible' or 'class incompatible'
                    end
                end
            end
        end
    end
    
    printf('[EmuBot] Scan complete: found %d compatible items', #compatibleItems)
    
    -- Sort by stats (basic comparison - prioritize AC, HP, then Mana)
    if compareItem then
        table.sort(compatibleItems, function(a, b)
            -- Calculate a simple score for comparison
            local scoreA = (a.ac or 0) + (a.hp or 0) * 0.5 + (a.mana or 0) * 0.3
            local scoreB = (b.ac or 0) + (b.hp or 0) * 0.5 + (b.mana or 0) * 0.3
            return scoreA > scoreB
        end)
    end
    
    return compatibleItems
end

-- Function to draw the local items comparison window
function botUI.drawLocalComparisonWindow()
    if not botUI.showLocalCompareWindow or not botUI.rightClickedBotItem then return end
    
    local windowFlags = ImGuiWindowFlags.None
    
EmuBot_PushRounding()
    ImGui.SetNextWindowSize(ImVec2(800, 600), ImGuiCond.FirstUseEver)
    local isOpen, shouldShow = ImGui.Begin('Local Items Comparison##LocalCompare', true, windowFlags)
    
    if not isOpen then
        botUI.showLocalCompareWindow = false
        botUI.rightClickedBotItem = nil
        ImGui.End()
        EmuBot_PopRounding()
        return
    end
    
    if shouldShow then
        local botItem = botUI.rightClickedBotItem
        local slotId = botItem.slotid
        local slotName = botItem.slotname or getSlotName(slotId) or "Unknown"
        
        -- Header information
        ImGui.Text(string.format("Local Items for %s Slot", slotName))
        ImGui.SameLine()
        ImGui.TextColored(0.7, 0.7, 0.7, 1.0, string.format("(Slot ID: %d)", slotId))
        
        ImGui.Spacing()
        ImGui.Text(string.format("Comparing against bot's current item: %s", botItem.name or "Unknown"))
        
        -- Try to get the bot name from the context
        local contextBotName = nil
        if botUI.selectedBot and botUI.selectedBot.name then
            contextBotName = botUI.selectedBot.name
        end
        
        -- Refresh button
        if ImGui.Button("Refresh Scan") then
            botUI.localCompareItems = botUI.findLocalItemsForSlot(slotId, botItem, contextBotName)
            printf('[EmuBot] Refreshed scan - found %d compatible items', #botUI.localCompareItems)
        end
        
        ImGui.SameLine()
        if ImGui.Button("Clear Cache") then
            botUI.scanLocalInventory(true) -- Force refresh
            botUI.localCompareItems = botUI.findLocalItemsForSlot(slotId, botItem, contextBotName)
            printf('[EmuBot] Cleared cache and rescanned - found %d compatible items', #botUI.localCompareItems)
        end
        
        ImGui.Separator()
        
        -- Item count and stats
        ImGui.Text(string.format("Found %d compatible items in your inventory", #botUI.localCompareItems))
        
        if #botUI.localCompareItems == 0 then
            ImGui.Spacing()
            ImGui.TextColored(0.9, 0.3, 0.3, 1.0, "No compatible items found in your inventory.")
            ImGui.Text("This could mean:")
            ImGui.BulletText("You don't have any items that can be equipped in this slot")
            ImGui.BulletText("Your items are in bank or other storage")
            ImGui.BulletText("Item scanning encountered an issue (check console)")
            ImGui.Spacing()
            ImGui.Text("Try the 'Clear Cache' button to force a fresh scan.")
        else
            ImGui.Spacing()
        end
        
        if #botUI.localCompareItems > 0 and ImGui.BeginTable('LocalItemsComparisonTable', 8,
                ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.Sortable) then
            ImGui.TableSetupColumn("Item", ImGuiTableColumnFlags.WidthStretch)
            ImGui.TableSetupColumn("Source", ImGuiTableColumnFlags.WidthFixed, 80)
            ImGui.TableSetupColumn("Icon", ImGuiTableColumnFlags.WidthFixed, 48)
            ImGui.TableSetupColumn("AC", ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn("HP", ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn("Mana", ImGuiTableColumnFlags.WidthFixed, 50)
            ImGui.TableSetupColumn("Class", ImGuiTableColumnFlags.WidthFixed, 80)
            ImGui.TableSetupColumn("Comparison", ImGuiTableColumnFlags.WidthFixed, 100)
            ImGui.TableHeadersRow()

            local sortSpecs = ImGui.TableGetSortSpecs()
            applyTableSort(botUI.localCompareItems, sortSpecs, {
                [1] = function(row) return row.name end,
                [2] = function(row) return row.source or '' end,
                [3] = function(row) return row.icon or 0 end,
                [4] = function(row) return row.ac or 0 end,
                [5] = function(row) return row.hp or 0 end,
                [6] = function(row) return row.mana or 0 end,
                [7] = function(row) return row.classCompatible and 1 or 0 end,
                [8] = function(row)
                    return (row.ac or 0) * 10000 + (row.hp or 0) * 100 + (row.mana or 0)
                end,
            })
            
            -- First, show the bot's current item
            ImGui.TableNextRow()
            ImGui.PushID("BotCurrentItem")
            
            ImGui.TableNextColumn()
            local botItemLabel = (botItem.name or "Unknown") .. "##BotItem"
            if ImGui.Selectable(botItemLabel) then
                local links = mq.ExtractLinks(botItem.itemlink)
                if links and #links > 0 and mq.ExecuteTextLink then
                    mq.ExecuteTextLink(links[1])
                end
            end
            
            ImGui.TableNextColumn()
            ImGui.TextColored(0.9, 0.5, 0.1, 1.0, "BOT")
            
            ImGui.TableNextColumn()
            if botItem.icon and botItem.icon > 0 then
                drawItemIcon(botItem.icon, 24, 24)
            else
                ImGui.Text("-")
            end
            
            ImGui.TableNextColumn()
            ImGui.TextColored(0.9, 0.75, 0.3, 1.0, tostring(botItem.ac or 0))
            
            ImGui.TableNextColumn()
            ImGui.TextColored(0.3, 0.85, 0.3, 1.0, tostring(botItem.hp or 0))
            
            ImGui.TableNextColumn()
            ImGui.TextColored(0.3, 0.6, 1.0, 1.0, tostring(botItem.mana or 0))
            
            ImGui.TableNextColumn()
            ImGui.Text(botItem.classes or "Unknown")
            
            ImGui.TableNextColumn()
            ImGui.Text("--")
            
            ImGui.PopID()
            
            -- Now show local character items
            for i, item in ipairs(botUI.localCompareItems) do
                ImGui.TableNextRow()
                ImGui.PushID(string.format("LocalItem_%d", i))
                
                ImGui.TableNextColumn()
                local itemLabel = (item.name or "Unknown") .. "##LocalItem" .. i
                if ImGui.Selectable(itemLabel) then
                    local links = mq.ExtractLinks(item.itemlink)
                    if links and #links > 0 and mq.ExecuteTextLink then
                        mq.ExecuteTextLink(links[1])
                    end
                end
                
                ImGui.TableNextColumn()
                local source = item.source == "equipped" and "Worn" or 
                              (item.sourceBag and "Bag " .. item.sourceBag or "Bag")
                ImGui.Text(source)
                
                ImGui.TableNextColumn()
                if item.icon and item.icon > 0 then
                    drawItemIcon(item.icon, 24, 24)
                else
                    ImGui.Text("-")
                end
                
                -- Compare AC values
                ImGui.TableNextColumn()
                local acDiff = (item.ac or 0) - (botItem.ac or 0)
                if acDiff > 0 then
                    ImGui.TextColored(0.0, 0.9, 0.0, 1.0, string.format("+%d", acDiff))
                elseif acDiff < 0 then
                    ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(acDiff))
                else
                    ImGui.Text(tostring(item.ac or 0))
                end
                
                -- Compare HP values
                ImGui.TableNextColumn()
                local hpDiff = (item.hp or 0) - (botItem.hp or 0)
                if hpDiff > 0 then
                    ImGui.TextColored(0.0, 0.9, 0.0, 1.0, string.format("+%d", hpDiff))
                elseif hpDiff < 0 then
                    ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(hpDiff))
                else
                    ImGui.Text(tostring(item.hp or 0))
                end
                
                -- Compare Mana values
                ImGui.TableNextColumn()
                local manaDiff = (item.mana or 0) - (botItem.mana or 0)
                if manaDiff > 0 then
                    ImGui.TextColored(0.0, 0.9, 0.0, 1.0, string.format("+%d", manaDiff))
                elseif manaDiff < 0 then
                    ImGui.TextColored(0.9, 0.0, 0.0, 1.0, tostring(manaDiff))
                else
                    ImGui.Text(tostring(item.mana or 0))
                end
                
                -- Show Class compatibility
                ImGui.TableNextColumn()
                ImGui.Text(item.classes or "Unknown")
                
                -- Overall comparison
                ImGui.TableNextColumn()
                local totalDiff = acDiff + hpDiff + manaDiff
                if totalDiff > 0 then
                    ImGui.TextColored(0.0, 0.9, 0.0, 1.0, "Better")
                elseif totalDiff < 0 then
                    ImGui.TextColored(0.9, 0.0, 0.0, 1.0, "Worse")
                else
                    ImGui.Text("Same")
                end
                
                ImGui.PopID()
            end
            
            ImGui.EndTable()
        end
        
        ImGui.Spacing()
        ImGui.Separator()
        
        if ImGui.Button("Close", 120, 0) then
            botUI.showLocalCompareWindow = false
            botUI.rightClickedBotItem = nil
        end
        
    end -- shouldShow
    
    ImGui.End()
    EmuBot_PopRounding()
end

local function drawAugmentTab(equippedItems)
    local flags = ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.Sortable
    if ImGui.BeginTable('BotAugmentTable', 8, flags) then
        ImGui.TableSetupColumn('Slot', ImGuiTableColumnFlags.WidthFixed, 110)
        ImGui.TableSetupColumn('Item', ImGuiTableColumnFlags.WidthStretch)
        for augIndex = 1, 6 do
            ImGui.TableSetupColumn(string.format('Aug %d', augIndex), ImGuiTableColumnFlags.WidthStretch)
        end
        ImGui.TableHeadersRow()

        local sortSpecs = ImGui.TableGetSortSpecs()
        applyTableSort(equippedItems, sortSpecs, {
            [1] = function(row) return tonumber(row.slotid) or 0 end,
            [2] = function(row) return row.name or '' end,
        })

        for _, item in ipairs(equippedItems or {}) do
            ImGui.TableNextRow()
            ImGui.PushID(string.format('aug_row_%s', tostring(item.slotid or 'unknown')))

            local slotName = getSlotName(item.slotid)
            ImGui.TableNextColumn()
            ImGui.Text(slotName)

            ImGui.TableNextColumn()
            local iconId = tonumber(item.icon or item.iconID or item.IconID or 0) or 0
            if iconId > 0 then
                drawItemIcon(iconId, 24, 24)
                ImGui.SameLine(0, 6)
            end
            local itemLabel = string.format('%s##aug_item_%s', item.name or 'Unknown Item', tostring(item.slotid or 'unknown'))
            if ImGui.Selectable(itemLabel, false) then
                local links = mq.ExtractLinks(item.itemlink)
                if links and #links > 0 and mq.ExecuteTextLink then
                    mq.ExecuteTextLink(links[1])
                end
            end
            if ImGui.IsItemHovered() then
                ImGui.BeginTooltip()
                ImGui.Text(item.name or 'Unknown Item')
                ImGui.Text(string.format('Slot: %s', slotName))
                ImGui.EndTooltip()
            end

            for augIndex = 1, 6 do
                ImGui.TableNextColumn()
                local augName = item['aug' .. augIndex .. 'Name']
                local augLink = item['aug' .. augIndex .. 'link']
                local augIcon = tonumber(item['aug' .. augIndex .. 'Icon']
                    or item['aug' .. augIndex .. 'icon']
                    or item['aug' .. augIndex .. 'IconID']
                    or 0) or 0

                if augName and augName ~= '' then
                    if augIcon > 0 then
                        drawItemIcon(augIcon, 20, 20)
                        ImGui.SameLine(0, 4)
                    end
                    local augLabel = string.format('%s##aug_slot_%d_%s', augName, augIndex, tostring(item.slotid or 'unknown'))
                    if augLink and augLink ~= '' then
                        if ImGui.Selectable(augLabel, false) then
                            local links = mq.ExtractLinks(augLink)
                            if links and #links > 0 and mq.ExecuteTextLink then
                                mq.ExecuteTextLink(links[1])
                            else
                                print(' No aug link found in the database.')
                            end
                        end
                    else
                        ImGui.Text(augName)
                    end

                    if ImGui.IsItemHovered() then
                        ImGui.BeginTooltip()
                        ImGui.Text(string.format('Augment: %s', augName))
                        ImGui.Text(string.format('Slot %d', augIndex))
                        ImGui.EndTooltip()
                    end
                else
                    ImGui.PushStyleColor(ImGuiCol.Text, 0.55, 0.55, 0.55, 0.8)
                    ImGui.Text('--')
                    ImGui.PopStyleColor()
                end
            end

            ImGui.PopID()
        end

        ImGui.EndTable()
    else
        ImGui.Text('No augment data available. Scan equipment to populate augments.')
    end
end

local function drawVisualTab(equippedItems)
    local slotLayout = getEquippedSlotLayout()
    local slotMap = {}
    for _, it in ipairs(equippedItems or {}) do
        local slotId = tonumber(it.slotid)
        if slotId then slotMap[slotId] = it end
    end

    local cellSize = 44
    local gridWidth = (cellSize + 4) * 4

    -- Left child: Equipped grid
    if ImGui.BeginChild('BotVisLeft', 250, 420, true) then
        if ImGui.BeginTable('BotEquippedVisual', 4,
            ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.SizingFixedFit) then
            for _, row in ipairs(slotLayout) do
                ImGui.TableNextRow(ImGuiTableRowFlags.None, cellSize + 6)
                for _, slotEntry in ipairs(row) do
                    ImGui.TableNextColumn()
                    if slotEntry ~= '' then
                        local slotId = tonumber(slotEntry) or 0
                        local slotName = getSlotName(slotId)
                        local item = slotMap[slotId]
                        ImGui.PushID(string.format('bot_vis_%s_%s', botUI.selectedBot and botUI.selectedBot.name or 'unknown', tostring(slotId)))

                        local clicked = ImGui.InvisibleButton('##btn', cellSize, cellSize)
                        local rightClicked = ImGui.IsItemClicked(ImGuiMouseButton.Right)
                        local minX, minY = ImGui.GetItemRectMin()
                        ImGui.SetCursorScreenPos(minX + 2, minY + 2)

                        if item and item.icon and item.icon > 0 then
                            drawItemIcon(item.icon, cellSize - 4, cellSize - 4)
                        else
                            local textWidth = ImGui.CalcTextSize(slotName)
                            local centerX = minX + (cellSize - textWidth) * 0.5
                            local centerY = minY + (cellSize - ImGui.GetTextLineHeight()) * 0.5
                            ImGui.SetCursorScreenPos(centerX, centerY)
                            ImGui.PushStyleColor(ImGuiCol.Text, 0.7, 0.7, 0.7, 1.0)
                            ImGui.Text(slotName)
                            ImGui.PopStyleColor()
                        end

                        if clicked then
                            botUI.selectedBotSlotID = slotId
                            botUI.selectedBotSlotName = slotName
                        end

                        if item and rightClicked then
                            local links = mq.ExtractLinks(item.itemlink)
                            if links and #links > 0 and mq.ExecuteTextLink then
                                mq.ExecuteTextLink(links[1])
                            end
                        end

                        if ImGui.IsItemHovered() then
                            ImGui.BeginTooltip()
                            ImGui.Text(slotName)
                            if item then
                                ImGui.Text(item.name or 'Unknown Item')
                                ImGui.Text(string.format('AC:%d  HP:%d  Mana:%d', tonumber(item.ac or 0), tonumber(item.hp or 0), tonumber(item.mana or 0)))
                                if item.icon and item.icon > 0 then
                                    ImGui.Text('Icon: ' .. tostring(item.icon))
                                end
                            else
                                ImGui.Text('(Empty)')
                            end
                            ImGui.EndTooltip()
                        end

                        ImGui.PopID()
                    else
                        ImGui.Dummy(cellSize, cellSize)
                    end
                end
            end
            ImGui.EndTable()
        end
    end
    ImGui.EndChild()

    ImGui.SameLine()

    -- Right child: Comparison
    if ImGui.BeginChild('BotVisRight', 0, 420, true) then
        if botUI.selectedBotSlotID then
            local slotName = botUI.selectedBotSlotName or getSlotName(botUI.selectedBotSlotID)
            local slotResults = collectBotSlotItems(botUI.selectedBotSlotID)
            ImGui.Separator()
            ImGui.Text(string.format('Slot %s across bots', slotName or tostring(botUI.selectedBotSlotID)))
            ImGui.SameLine()
            if ImGui.SmallButton('Clear##BotSlotSelection') then
                botUI.selectedBotSlotID = nil
                botUI.selectedBotSlotName = nil
                slotResults = {}
            end
            ImGui.SameLine()
            if ImGui.SmallButton('Scan Items##BotSlotScan') then
                local seen = {}
                local pending = {}
                local allItems = {}
                for _, entry in ipairs(slotResults) do
                    local item = entry.item
                    if item and item.itemlink and item.itemlink ~= '' then
                        local key = tostring(item)
                        if not seen[key] then
                            seen[key] = true
                            table.insert(allItems, { item = item, bot = entry.bot })
                            local missing = (not item.ac and not item.hp and not item.mana)
                                or ((tonumber(item.ac or 0) == 0)
                                    and (tonumber(item.hp or 0) == 0)
                                    and (tonumber(item.mana or 0) == 0))
                            if missing then
                                table.insert(pending, { item = item, bot = entry.bot })
                            end
                        end
                    end
                end
                local toScan = pending
                if #toScan == 0 then
                    toScan = allItems
                end
                for _, pair in ipairs(toScan) do
                    botUI.enqueueItemScan(pair.item, pair.bot)
                end
                printf('Queued scan for %d slot item(s) in %s', #toScan, slotName or tostring(botUI.selectedBotSlotID))
            end
            ImGui.SameLine()
            do
                local cur = botUI.showClassInVisual and true or false
                local newVal, pressed = ImGui.Checkbox('Show Class##vis_showclass', cur)
                if pressed then botUI.showClassInVisual = newVal and true or false end
            end
            if #slotResults == 0 then
                ImGui.Text('No bot data available for this slot yet.')
            else
                local _cols = botUI.showClassInVisual and 7 or 6
                if ImGui.BeginTable('BotSlotComparison', _cols,
                        ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.Sortable) then
                    ImGui.TableSetupColumn('Bot', ImGuiTableColumnFlags.WidthFixed, 120)
                    if botUI.showClassInVisual then
                        ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 100)
                    end
                    ImGui.TableSetupColumn('Icon', ImGuiTableColumnFlags.WidthFixed, 48)
                    ImGui.TableSetupColumn('Item', ImGuiTableColumnFlags.WidthStretch)
                    ImGui.TableSetupColumn('AC', ImGuiTableColumnFlags.WidthFixed, 50)
                    ImGui.TableSetupColumn('HP', ImGuiTableColumnFlags.WidthFixed, 50)
                    ImGui.TableSetupColumn('Mana', ImGuiTableColumnFlags.WidthFixed, 50)
                    ImGui.TableHeadersRow()

                    local sortSpecs = ImGui.TableGetSortSpecs()
                    applyTableSort(slotResults, sortSpecs, {
                        [1] = function(row) return row.bot or '' end,
                        [2] = botUI.showClassInVisual and function(row)
                            return get_bot_class_abbrev(row.bot) or ''
                        end or nil,
                        [botUI.showClassInVisual and 3 or 2] = function(row)
                            return row.item and row.item.icon or 0
                        end,
                        [botUI.showClassInVisual and 4 or 3] = function(row)
                            return row.item and row.item.name or ''
                        end,
                        [botUI.showClassInVisual and 5 or 4] = function(row)
                            return row.item and row.item.ac or 0
                        end,
                        [botUI.showClassInVisual and 6 or 5] = function(row)
                            return row.item and row.item.hp or 0
                        end,
                        [botUI.showClassInVisual and 7 or 6] = function(row)
                            return row.item and row.item.mana or 0
                        end,
                    })

                    for _, entry in ipairs(slotResults) do
                        ImGui.TableNextRow()
                        ImGui.TableNextColumn()
                        local botLabel = (entry.bot or 'Unknown') .. '##vis_target_' .. tostring(entry.bot or '?')
                        if ImGui.Selectable(botLabel, false, ImGuiSelectableFlags.None) then
                            local botName = entry.bot
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
                            ImGui.SetTooltip('Click to target ' .. (entry.bot or 'bot'))
                        end

                        if botUI.showClassInVisual then
                            ImGui.TableNextColumn()
                            local cls = get_bot_class_abbrev(entry.bot)
                            ImGui.Text(cls or '-')
                        end

                        ImGui.TableNextColumn()
                        if entry.item and entry.item.icon and entry.item.icon > 0 then
                            drawItemIcon(entry.item.icon, 24, 24)
                        else
                            ImGui.Text('-')
                        end

                        ImGui.TableNextColumn()
                        if entry.item then
                            local label = (entry.item.name or 'Unknown Item') .. '##' .. (entry.bot or 'unknown')
                            local clicked = ImGui.Selectable(label)
                            local rightClicked = ImGui.IsItemClicked(ImGuiMouseButton.Right)
                            
                            if clicked then
                                local links = mq.ExtractLinks(entry.item.itemlink)
                                if links and #links > 0 and mq.ExecuteTextLink then
                                    mq.ExecuteTextLink(links[1])
                                end
                            elseif rightClicked then
                                botUI.rightClickedBotItem = entry.item
                                local slotId = entry.item.slotid
                                botUI.localCompareItems = botUI.findLocalItemsForSlot(slotId, entry.item, entry.bot)
                                botUI.showLocalCompareWindow = true
                                printf('[EmuBot] Found %d local items compatible with %s slot', #botUI.localCompareItems, getSlotName(slotId) or 'unknown')
                            end
                        else
                            ImGui.Text('-')
                        end

                        ImGui.TableNextColumn()
                        if entry.item then
                            ImGui.TextColored(0.9, 0.75, 0.3, 1.0, tostring(entry.item.ac or 0))
                        else
                            ImGui.Text('-')
                        end

                        ImGui.TableNextColumn()
                        if entry.item then
                            ImGui.TextColored(0.3, 0.85, 0.3, 1.0, tostring(entry.item.hp or 0))
                        else
                            ImGui.Text('-')
                        end

                        ImGui.TableNextColumn()
                        if entry.item then
                            ImGui.TextColored(0.3, 0.6, 1.0, 1.0, tostring(entry.item.mana or 0))
                        else
                            ImGui.Text('-')
                        end
                    end

                    ImGui.EndTable()
                end
            end
        else
            ImGui.Text('Select a slot in the grid to compare across bots.')
        end
    end
    ImGui.EndChild()
end

local function drawTableTab(equippedItems)
    if ImGui.BeginTable('BotEquippedTable', 7,
            ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.Sortable) then
        ImGui.TableSetupColumn('Slot', ImGuiTableColumnFlags.WidthFixed, 100)
        ImGui.TableSetupColumn('Icon', ImGuiTableColumnFlags.WidthFixed, 48)
        ImGui.TableSetupColumn('Item Name', ImGuiTableColumnFlags.WidthStretch)
        ImGui.TableSetupColumn('AC', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('HP', ImGuiTableColumnFlags.WidthFixed, 70)
        ImGui.TableSetupColumn('Mana', ImGuiTableColumnFlags.WidthFixed, 70)
        ImGui.TableSetupColumn('Action', ImGuiTableColumnFlags.WidthFixed, 120)
        ImGui.TableHeadersRow()

        local sortSpecs = ImGui.TableGetSortSpecs()
        applyTableSort(equippedItems, sortSpecs, {
            [1] = function(row) return tonumber(row.slotid) or 0 end,
            [2] = function(row) return row.icon or 0 end,
            [3] = function(row) return row.name or '' end,
            [4] = function(row) return row.ac or 0 end,
            [5] = function(row) return row.hp or 0 end,
            [6] = function(row) return row.mana or 0 end,
        })

        for _, item in ipairs(equippedItems or {}) do
            ImGui.TableNextRow()
            ImGui.PushID(string.format('bot_item_%s_%s', botUI.selectedBot and botUI.selectedBot.name or 'unknown', item.slotid or 'unknown'))

            local slotName = getSlotName(item.slotid)
            ImGui.TableNextColumn()
            ImGui.Text(slotName)

            ImGui.TableNextColumn()
            local iconId = tonumber(item.icon or item.iconID or 0) or 0
            if iconId > 0 then
                if drawItemIcon then
                    drawItemIcon(iconId, 24, 24)
                else
                    ImGui.Text(tostring(iconId))
                end
            else
                ImGui.Text('-')
            end

            ImGui.TableNextColumn()
            local itemName = item.name or 'Unknown Item'
            if ImGui.Selectable(itemName) then
                local links = mq.ExtractLinks(item.itemlink)
                if links and #links > 0 then
                    mq.ExecuteTextLink(links[1])
                else
                    print(' No item link found in the database.')
                end
            end

            if ImGui.IsItemHovered() then
                ImGui.BeginTooltip()
                ImGui.Text('Item: ' .. itemName)
                ImGui.Text('Slot ID: ' .. tostring(item.slotid))
                ImGui.Text(string.format('AC: %s  HP: %s  Mana: %s', tostring(item.ac or 0), tostring(item.hp or 0), tostring(item.mana or 0)))
                if item.itemlink and item.itemlink ~= '' then
                    ImGui.Text('Has Link: YES')
                else
                    ImGui.Text('Has Link: NO')
                end
                if item.rawline then
                    ImGui.Text('Has Raw Line: YES')
                else
                    ImGui.Text('Has Raw Line: NO')
                end
                ImGui.Text('Click to inspect item')
                ImGui.EndTooltip()
            end

            ImGui.TableNextColumn()
            ImGui.Text(tostring(item.ac or 0))
            ImGui.TableNextColumn()
            ImGui.Text(tostring(item.hp or 0))
            ImGui.TableNextColumn()
            ImGui.Text(tostring(item.mana or 0))

            ImGui.TableNextColumn()
            if (not item.ac or not item.hp or not item.mana)
                or ((item.ac == 0) and (item.hp == 0) and (item.mana == 0)) then
if ImGui.Button('Scan##' .. tostring(item.slotid or 'unknown')) then
                    botUI.enqueueItemScan(item, botUI.selectedBot and botUI.selectedBot.name or nil)
                end
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Open ItemDisplay to scrape stats')
                end
                ImGui.SameLine()
            end

            if ImGui.Button('Unequip##' .. tostring(item.slotid or 'unknown')) then
                if botUI.selectedBot and botUI.selectedBot.name and item.slotid then
                    local botName = botUI.selectedBot.name
                    local slotId = item.slotid

                    enqueueTask(function()
                        local botSpawn = mq.TLO.Spawn(string.format('= %s', botName))
                        if botSpawn.ID() and botSpawn.ID() > 0 then
                            mq.cmdf('/target id %d', botSpawn.ID())
                            printf('Targeting %s for unequip...', botName)

                            local maxAttempts = 10
                            local attempts = 0
                            local function targetCheckTask()
                                if mq.TLO.Target.Name() == botName then
                                    bot_inventory.requestBotUnequip(botName, slotId)
                                    return true
                                elseif mq.TLO.Target.ID() == 0 then
                                    mq.cmdf('/target "%s"', botName)
                                    return false
                                elseif mq.TLO.Target.Name() ~= botName then
                                    print('Could not target bot')
                                    return true
                                end
                                return false
                            end

                            local function queueTargetCheck()
                                enqueueTask(function()
                                    attempts = attempts + 1
                                    if targetCheckTask() then
                                        return true
                                    end

                                    if attempts < maxAttempts then
                                        queueTargetCheck()
                                    else
                                        print('Timeout targeting bot for unequip')
                                    end
                                    return true
                                end)
                            end

                            queueTargetCheck()
                        else
                            print('Could not find bot spawn for unequip command')
                        end
                    end)

                    printf('Queued unequip request for %s slot %s', botName, slotId)
                end
            end

            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Unequip this item from the bot')
            end

            ImGui.PopID()
        end

        ImGui.EndTable()
    end
end

 -- Helper: Return a 3-letter class abbreviation for a bot, when available
get_bot_class_abbrev = function(botName)
    local meta = bot_inventory and bot_inventory.bot_list_capture_set and bot_inventory.bot_list_capture_set[botName]
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
    for key, val in pairs(map) do
        if up:find(key) then return val end
    end
    return 'UNK'
end

-- Draw the Bot Groups tab
function drawBotGroupsTab()
    -- Header with refresh button
    if ImGui.Button('Refresh Groups') then
        bot_groups.refresh_groups()
    end
    
    ImGui.SameLine()
    ImGui.Text(string.format('Groups: %d', #bot_groups.groups))
    
    if bot_groups.operationStatus ~= "" then
        ImGui.SameLine()
        ImGui.TextColored(0.2, 0.8, 0.2, 1.0, bot_groups.operationStatus)
    end
    
    ImGui.Separator()
    
    -- Create new group section
    ImGui.Text('Create New Group:')
    ImGui.PushItemWidth(200)
    bot_groups.newGroupName = ImGui.InputText('##NewGroupName', bot_groups.newGroupName or '')
    ImGui.SameLine()
    bot_groups.newGroupDescription = ImGui.InputText('##NewGroupDesc', bot_groups.newGroupDescription or '')
    ImGui.PopItemWidth()
    
    ImGui.SameLine()
    if ImGui.Button('Create Group') then
        if bot_groups.newGroupName and bot_groups.newGroupName ~= "" then
            local ok, result = bot_groups.create_group(bot_groups.newGroupName, bot_groups.newGroupDescription)
            if ok then
                bot_groups.newGroupName = ""
                bot_groups.newGroupDescription = ""
            else
                printf('[EmuBot] Failed to create group: %s', tostring(result))
            end
        end
    end
    
    ImGui.Separator()
    
    -- Groups list
    if #bot_groups.groups == 0 then
        ImGui.Text('No groups created yet. Create a group above to get started.')
        return
    end
    
    -- Groups table
    if ImGui.BeginTable('GroupsTable', 6,
            ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Resizable + ImGuiTableFlags.Sortable) then
        ImGui.TableSetupColumn('Group', ImGuiTableColumnFlags.WidthStretch)
        ImGui.TableSetupColumn('Members', ImGuiTableColumnFlags.WidthFixed, 80)
        ImGui.TableSetupColumn('Status', ImGuiTableColumnFlags.WidthFixed, 100)
        ImGui.TableSetupColumn('Actions', ImGuiTableColumnFlags.WidthStretch)
        ImGui.TableSetupColumn('Edit', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableSetupColumn('Delete', ImGuiTableColumnFlags.WidthFixed, 60)
        ImGui.TableHeadersRow()

        local sortSpecs = ImGui.TableGetSortSpecs()
        applyTableSort(bot_groups.groups, sortSpecs, {
            [1] = function(row) return row.name or '' end,
            [2] = function(row)
                return row.members and #row.members or 0
            end,
            [3] = function(row)
                return row.status or ''
            end,
        })

        for _, group in ipairs(bot_groups.groups) do
            ImGui.TableNextRow()
            ImGui.PushID('group_' .. tostring(group.id))
            
            -- Group name and description
            ImGui.TableNextColumn()
            ImGui.Text(group.name or 'Unnamed')
            if group.description and group.description ~= "" then
                ImGui.Text(group.description)
            end
            
            -- Member count
            ImGui.TableNextColumn()
            local memberCount = group.members and #group.members or 0
            ImGui.Text(tostring(memberCount))
            
            -- Status
            ImGui.TableNextColumn()
            if memberCount > 0 then
                local status = bot_groups.get_group_status(group.id)
                local color = status.percentage == 100 and {0.2, 0.8, 0.2, 1.0} or 
                              status.percentage > 0 and {0.8, 0.8, 0.2, 1.0} or 
                              {0.8, 0.2, 0.2, 1.0}
                ImGui.TextColored(color[1], color[2], color[3], color[4], 
                    string.format('%d/%d (%d%%)', status.spawned, status.total, status.percentage))
            else
                ImGui.TextColored(0.5, 0.5, 0.5, 1.0, 'Empty')
            end
            
            -- Actions
            ImGui.TableNextColumn()
            if memberCount > 0 then
                if ImGui.SmallButton('Spawn') then
                    bot_groups.spawn_group(group.id)
                end
                ImGui.SameLine()
                if ImGui.SmallButton('Invite') then
                    -- Use enqueueTask to avoid non-yieldable thread error from mq.delay()
                    enqueueTask(function()
                        bot_groups.invite_group(group.id)
                    end)
                end
                ImGui.SameLine()
                if ImGui.SmallButton('Spawn & Invite') then
                    -- Use a non-blocking approach
                    enqueueTask(function()
                        bot_groups.spawn_and_invite_group(group.id)
                    end)
                end
            else
                ImGui.TextColored(0.5, 0.5, 0.5, 1.0, 'No members')
            end
            
            -- Edit button
            ImGui.TableNextColumn()
            if ImGui.SmallButton('Edit') then
                bot_groups.editingGroup = group
                bot_groups.selectedGroup = group
            end
            
            -- Delete button
            ImGui.TableNextColumn()
            if ImGui.SmallButton('Delete') then
                bot_groups.delete_group(group.id)
            end
            
            ImGui.PopID()
        end
        
        ImGui.EndTable()
    end
    
    -- Group editing section
    if bot_groups.editingGroup then
        ImGui.Separator()
        ImGui.Text(string.format('Editing Group: %s', bot_groups.editingGroup.name or 'Unknown'))
        
        -- Available bots list
        local availableBots = bot_inventory.getAllBots() or {}
        local currentMembers = {}
        
        -- Build current members lookup
        if bot_groups.editingGroup.members then
            for _, member in ipairs(bot_groups.editingGroup.members) do
                currentMembers[member.bot_name] = true
            end
        end
        
        -- Show current members
        ImGui.Text('Current Members:')
        if bot_groups.editingGroup.members and #bot_groups.editingGroup.members > 0 then
            if ImGui.BeginTable('CurrentMembers', 4, ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Sortable) then
                ImGui.TableSetupColumn('Bot Name', ImGuiTableColumnFlags.WidthStretch)
                ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 60)
                ImGui.TableSetupColumn('Status', ImGuiTableColumnFlags.WidthFixed, 80)
                ImGui.TableSetupColumn('Remove', ImGuiTableColumnFlags.WidthFixed, 60)
                ImGui.TableHeadersRow()

                local sortSpecs = ImGui.TableGetSortSpecs()
                applyTableSort(bot_groups.editingGroup.members, sortSpecs, {
                    [1] = function(row) return row.bot_name or '' end,
                    [2] = function(row) return get_bot_class_abbrev(row.bot_name) or '' end,
                    [3] = function(row)
                        return is_bot_spawned(row.bot_name) and 1 or 0
                    end,
                })
                
                for _, member in ipairs(bot_groups.editingGroup.members) do
                    ImGui.TableNextRow()
                    
                    ImGui.TableNextColumn()
                    ImGui.Text(member.bot_name)
                    
                    ImGui.TableNextColumn()
                    local cls = get_bot_class_abbrev(member.bot_name)
                    ImGui.Text(cls)
                    
                    ImGui.TableNextColumn()
                    local spawned = is_bot_spawned(member.bot_name)
                    if spawned then
                        ImGui.TextColored(0.2, 0.8, 0.2, 1.0, 'Spawned')
                    else
                        ImGui.TextColored(0.8, 0.2, 0.2, 1.0, 'Despawned')
                    end
                    
                    ImGui.TableNextColumn()
                    ImGui.PushID('remove_' .. member.bot_name)
                    if ImGui.SmallButton('Remove') then
                        bot_groups.remove_bot_from_group(bot_groups.editingGroup.id, member.bot_name)
                        -- Refresh the editing group
                        for _, g in ipairs(bot_groups.groups) do
                            if g.id == bot_groups.editingGroup.id then
                                bot_groups.editingGroup = g
                                break
                            end
                        end
                    end
                    ImGui.PopID()
                end
                
                ImGui.EndTable()
            end
        else
            ImGui.Text('No members in this group yet.')
        end
        
        -- Add bots section
        ImGui.Spacing()
        ImGui.Text('Add Bots to Group:')
        
        if #availableBots > 0 then
            if ImGui.BeginTable('AvailableBots', 4,
                    ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Sortable) then
                ImGui.TableSetupColumn('Bot Name', ImGuiTableColumnFlags.WidthStretch)
                ImGui.TableSetupColumn('Class', ImGuiTableColumnFlags.WidthFixed, 60)
                ImGui.TableSetupColumn('Status', ImGuiTableColumnFlags.WidthFixed, 80)
                ImGui.TableSetupColumn('Add', ImGuiTableColumnFlags.WidthFixed, 60)
                ImGui.TableHeadersRow()

                local sortSpecs = ImGui.TableGetSortSpecs()
                applyTableSort(availableBots, sortSpecs, {
                    [1] = function(row) return row or '' end,
                    [2] = function(row) return get_bot_class_abbrev(row) or '' end,
                    [3] = function(row) return is_bot_spawned(row) and 1 or 0 end,
                })
                
                for _, botName in ipairs(availableBots) do
                    if not currentMembers[botName] then
                        ImGui.TableNextRow()
                        
                        ImGui.TableNextColumn()
                        ImGui.Text(botName)
                        
                        ImGui.TableNextColumn()
                        local cls = get_bot_class_abbrev(botName)
                        ImGui.Text(cls)
                        
                        ImGui.TableNextColumn()
                        local spawned = is_bot_spawned(botName)
                        if spawned then
                            ImGui.TextColored(0.2, 0.8, 0.2, 1.0, 'Spawned')
                        else
                            ImGui.TextColored(0.8, 0.2, 0.2, 1.0, 'Despawned')
                        end
                        
                        ImGui.TableNextColumn()
                        ImGui.PushID('add_' .. botName)
                        if ImGui.SmallButton('Add') then
                            bot_groups.add_bot_to_group(bot_groups.editingGroup.id, botName)
                            -- Refresh the editing group
                            for _, g in ipairs(bot_groups.groups) do
                                if g.id == bot_groups.editingGroup.id then
                                    bot_groups.editingGroup = g
                                    break
                                end
                            end
                        end
                        ImGui.PopID()
                    end
                end
                
                ImGui.EndTable()
            end
        else
            ImGui.Text('No bots available. Refresh bot list from the Bot Management tab.')
        end
        
        -- Close editing
        ImGui.Spacing()
        if ImGui.Button('Done Editing') then
            bot_groups.editingGroup = nil
        end
    end
end

function is_bot_spawned(name)
    local s = mq.TLO.Spawn(string.format('= %s', name))
    return s and s.ID and s.ID() and s.ID() > 0
end


function botUI.drawBotInventoryWindow()
    if not botUI.showWindow then return end

    syncSelectedBotData()

    local equippedItems = {}
    if botUI.selectedBot and botUI.selectedBot.data and botUI.selectedBot.data.equipped then
        equippedItems = botUI.selectedBot.data.equipped
    end

EmuBot_PushRounding()
    ImGui.SetNextWindowSize(ImVec2(600, 400), ImGuiCond.FirstUseEver)
    local isOpen, shouldShow = ImGui.Begin('Bot Inventory Viewer##EmuBot', true, ImGuiWindowFlags.None)
    if not isOpen then
        botUI.showWindow = false
        botUI.selectedBot = nil
        botUI.selectedBotSlotID = nil
        botUI.selectedBotSlotName = nil
        ImGui.End()
        EmuBot_PopRounding()
        return
    end

    if shouldShow then
        local windowWidth = ImGui.GetWindowWidth()
        local botList = collectBotNames()
        local displayList = {}
        for _, name in ipairs(botList) do
            if botUI.viewerShowClassInSelector then
                local cls = get_bot_class_abbrev(name)
                table.insert(displayList, cls)
            else
                if botUI.viewerAppendClassAbbrevInSelector then
                    local cls = get_bot_class_abbrev(name)
                    table.insert(displayList, string.format('%s [%s]', name, cls))
                else
                    table.insert(displayList, name)
                end
            end
        end
        local currentBotName = botUI.selectedBot and botUI.selectedBot.name or ''
        local comboLabel = currentBotName ~= '' and currentBotName or (#botList > 0 and 'Select Bot' or 'No Bots')

        -- Controls row: refresh / clear buttons then selector
        if ImGui.Button('Refresh Bot List') then
            refreshBotList()
        end
        ImGui.SameLine()
        if ImGui.Button('Clear Bot Cache') then
            if bot_inventory then
                bot_inventory.bot_inventories = {}
                bot_inventory.cached_bot_list = {}
                bot_inventory.bot_list_capture_set = {}
            end
            botUI.selectedBot = nil
            botUI._itemStatCache = {}
        end

        -- Toggle HotBar button
        ImGui.SameLine()
        local hb_on = commandsui and commandsui.is_visible and commandsui.is_visible() or false
        if hb_on then
            ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.6, 0.2, 0.9)
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.25, 0.7, 0.25, 1.0)
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.15, 0.5, 0.15, 1.0)
        else
            ImGui.PushStyleColor(ImGuiCol.Button, 0.4, 0.4, 0.4, 0.9)
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.5, 0.5, 0.5, 1.0)
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.35, 0.35, 0.35, 1.0)
        end
        if ImGui.Button('HotBar') then
            if commandsui and commandsui.toggle then commandsui.toggle() end
        end
        ImGui.PopStyleColor(3)

        ImGui.SameLine()
        ImGui.Text('Viewing bot:')
        ImGui.SameLine()
        ImGui.SetNextItemWidth(math.max(150, math.min(windowWidth * 0.35, 250)))
        if #botList > 0 then
            
            -- Find current bot index for combo (MQ Lua binding appears 1-based)
            local currentIndex1 = 0  -- 0 = no selection
            for i, name in ipairs(botList) do
                if name == currentBotName then
                    currentIndex1 = i
                    break
                end
            end

            -- Use ImGui.Combo and treat index as 1-based
            local selectedIndex1, changed = ImGui.Combo('##BotInventorySelect', currentIndex1, displayList)
            
            -- Process selection when changed
            if changed and selectedIndex1 ~= nil and selectedIndex1 >= 1 and selectedIndex1 <= #botList then
                local luaIndex = selectedIndex1 -- 1-based
                local botName = botList[luaIndex]
                if botName and botName ~= '' then
                    -- Always process the selection (even if same bot) to allow refresh
                    local botData = bot_inventory and bot_inventory.getBotInventory and bot_inventory.getBotInventory(botName)
                    if (not botData or not botData.equipped) then
                        botUI._enqueueBotInventoryFetch(botName)
                    end
                    botUI.selectedBot = { name = botName }
                    if botData then
                        botUI.selectedBot.data = botData
                    else
                        syncSelectedBotData()
                        botData = botUI.selectedBot and botUI.selectedBot.data or nil
                    end
                    botUI.selectedBotSlotID = nil
                    botUI.selectedBotSlotName = nil
                    equippedItems = (botData and botData.equipped) or {}
                    currentBotName = botName
                    if botUI.viewerShowClassInSelector then
                        comboLabel = get_bot_class_abbrev(botName)
                    else
                        if botUI.viewerAppendClassAbbrevInSelector then
                            comboLabel = string.format('%s [%s]', botName, get_bot_class_abbrev(botName))
                        else
                            comboLabel = botName
                        end
                    end
                end
            elseif changed then
                printf('[EmuBot] Warning: Invalid bot selection index %s (list size: %d)', tostring(selectedIndex1), #botList)
            end
        else
            ImGui.Text(comboLabel)
        end

        local buttonWidth = 80
        local buttonSpacing = ImGui.GetStyle().ItemSpacing.x
        local buttonCount = 3
        local totalButtonWidth = buttonWidth * buttonCount + buttonSpacing * (buttonCount - 1)

        ImGui.SameLine()
        ImGui.SetCursorPosX(math.max(0, windowWidth - totalButtonWidth - 10))

        if ImGui.Button('Refresh', buttonWidth, 0) then
            if botUI.selectedBot and botUI.selectedBot.name then
                bot_inventory.requestBotInventory(botUI.selectedBot.name)
                printf('Refreshing inventory for bot: %s', botUI.selectedBot.name)
            end
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Refresh inventory data from bot\nAutomatically detects and scans items with mismatched or missing stats')
        end

        ImGui.SameLine()

        if ImGui.Button('Scan Bot', buttonWidth, 0) then
            local itemsToScan = {}
            for _, it in ipairs(equippedItems or {}) do
                local missingBasic = (not it.ac and not it.hp and not it.mana)
                    or ((tonumber(it.ac or 0) == 0) and (tonumber(it.hp or 0) == 0) and (tonumber(it.mana or 0) == 0))
                local sid = tonumber(it.slotid or -1) or -1
                local missingWeapon = (sid == 11 or sid == 13 or sid == 14) and ((tonumber(it.damage or 0) == 0) or (tonumber(it.delay or 0) == 0))
                if missingBasic or missingWeapon then
                    table.insert(itemsToScan, it)
                end
            end
            if #itemsToScan == 0 then itemsToScan = equippedItems or {} end
            for _, it in ipairs(itemsToScan) do
                botUI.enqueueItemScan(it, botUI.selectedBot and botUI.selectedBot.name or nil)
            end
            printf('Queued scan for %d item(s)', #itemsToScan)
        end

        ImGui.SameLine()

if ImGui.Button('Close', buttonWidth, 0) then
            botUI.showWindow = false
            botUI.selectedBot = nil
            botUI.selectedBotSlotID = nil
            botUI.selectedBotSlotName = nil
            ImGui.End()
            EmuBot_PopRounding()
            return
        end
        
        ImGui.Separator()

        -- Scan All Bots section
        ImGui.Text('Bulk Operations:')
        ImGui.SameLine()
        
        if not botUI._scanAllActive then
            if ImGui.Button('Scan All', buttonWidth, 0) then
                -- Always refresh the bot list first and show the confirmation popup.
                if bot_inventory and bot_inventory.refreshBotList then
                    bot_inventory.refreshBotList()
                end
                -- Store the original camp setting before showing popup
                botUI._originalCampSetting = botUI.disableCampDuringScanAll
                -- Open the confirmation popup (we'll kick off after refresh on YES/NO)
                ImGui.OpenPopup('Scan All Bots##ScanAllConfirm')
            end
            if ImGui.IsItemHovered() then
                local tooltipText = 'Spawn all bots and gather their inventory data'
                if botUI.disableCampDuringScanAll then
                    tooltipText = tooltipText .. ' (camping disabled - bots will remain spawned)'
                else
                    tooltipText = tooltipText .. ', then camp them'
                end
                ImGui.SetTooltip(tooltipText)
            end
        else
            if ImGui.Button('Cancel Scan', buttonWidth, 0) then
                botUI.stopScanAllBots()
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Stop the current scan all bots operation')
            end
        end
        
        -- Toggle switch for disable camp setting
        ImGui.SameLine()
        ImGui.Text('Camp After Scan?:')
        ImGui.SameLine()
        
        -- Create a styled toggle switch
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 12.0)
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, ImVec2(8, 4))
        
        if botUI.disableCampDuringScanAll then
            -- ON state - green background with white text
            ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.7, 0.2, 0.8)
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.3, 0.8, 0.3, 0.9)
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.1, 0.6, 0.1, 1.0)
            ImGui.PushStyleColor(ImGuiCol.Text, 1.0, 1.0, 1.0, 1.0)
            if ImGui.Button(' NO ') then
                botUI.disableCampDuringScanAll = false
            end
        else
            -- OFF state - red background with white text
            ImGui.PushStyleColor(ImGuiCol.Button, 0.7, 0.2, 0.2, 0.8)
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.8, 0.3, 0.3, 0.9)
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.6, 0.1, 0.1, 1.0)
            ImGui.PushStyleColor(ImGuiCol.Text, 1.0, 1.0, 1.0, 1.0)
            if ImGui.Button('YES') then
                botUI.disableCampDuringScanAll = true
            end
        end
        
        ImGui.PopStyleColor(4)
        ImGui.PopStyleVar(2)
        
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Toggle: Disable camping bots after scan (useful when scanning fewer than spawn limit)')
        end
        
        -- Quick Groups section
        if #bot_groups.groups > 0 then
            ImGui.SameLine()
            ImGui.Text('Quick Groups:')
            ImGui.SameLine()
            
            -- Show first few groups with quick spawn buttons
            local groupsShown = 0
            for _, group in ipairs(bot_groups.groups) do
                if groupsShown >= 3 then break end -- Limit to 3 groups to avoid UI clutter
                if group.members and #group.members > 0 then
                    ImGui.SameLine()
                    local status = bot_groups.get_group_status(group.id)
                    local buttonText = string.format('%s (%d/%d)', group.name, status.spawned, status.total)
                    
                    -- Color button based on spawn status
                    if status.percentage == 100 then
                        ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.7, 0.2, 0.8)
                        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.3, 0.8, 0.3, 0.9)
                        ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.1, 0.6, 0.1, 1.0)
                    elseif status.percentage > 0 then
                        ImGui.PushStyleColor(ImGuiCol.Button, 0.8, 0.6, 0.2, 0.8)
                        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.9, 0.7, 0.3, 0.9)
                        ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.7, 0.5, 0.1, 1.0)
                    else
                        ImGui.PushStyleColor(ImGuiCol.Button, 0.6, 0.6, 0.6, 0.8)
                        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.7, 0.7, 0.7, 0.9)
                        ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.5, 0.5, 0.5, 1.0)
                    end
                    
                    if ImGui.SmallButton(buttonText) then
                        enqueueTask(function()
                            bot_groups.spawn_and_invite_group(group.id)
                        end)
                    end
                    
                    ImGui.PopStyleColor(3)
                    
                    if ImGui.IsItemHovered() then
                        ImGui.SetTooltip(string.format('Spawn and invite group "%s"\n%d members (%d%% spawned)', 
                            group.name, status.total, status.percentage))
                    end
                    
                    groupsShown = groupsShown + 1
                end
            end
        end
        
        -- Show progress if scan is active
        if botUI._scanAllActive and botUI._scanAllProgress and botUI._scanAllProgress ~= '' then
            ImGui.SameLine()
            ImGui.TextColored(0.3, 0.85, 0.3, 1.0, botUI._scanAllProgress)
        end
        
        -- Show item scanning queue status
        if #botUI._scanQueue > 0 then
            ImGui.SameLine()
            local statusText = string.format('(%d items scanning)', #botUI._scanQueue)
            if botUI._autoScannedItems > 0 then
                statusText = statusText .. string.format(' [%d auto-scanned]', botUI._autoScannedItems)
            end
            ImGui.TextColored(0.3, 0.6, 1.0, 1.0, statusText)
        elseif botUI._autoScannedItems > 0 then
            ImGui.SameLine()
            ImGui.TextColored(0.2, 0.8, 0.2, 1.0, string.format('(%d items auto-scanned)', botUI._autoScannedItems))
        end

        ImGui.Separator()

if ImGui.BeginTabBar('BotEquippedViewTabs', ImGuiTabBarFlags.Reorderable) then
            if ImGui.BeginTabItem('Visual') then
                drawVisualTab(equippedItems)
                ImGui.EndTabItem()
            end

            if ImGui.BeginTabItem('Table') then
                drawTableTab(equippedItems)
                ImGui.EndTabItem()
            end

            if ImGui.BeginTabItem('Augments') then
                drawAugmentTab(equippedItems)
                ImGui.EndTabItem()
            end

            if ImGui.BeginTabItem('Bot Management') then
                bot_management.draw()
                ImGui.EndTabItem()
            end
            
            if ImGui.BeginTabItem('Bot Groups') then
                drawBotGroupsTab()
                ImGui.EndTabItem()
            end

            if ImGui.BeginTabItem('Raid Manager') then
                -- Pass viewer display preference to raid manager
                if raid_manager and raid_manager.set_show_class_names then
                    raid_manager.set_show_class_names(botUI.viewerShowClassInSelector)
                end
                raid_manager.draw_tab()
                ImGui.EndTabItem()
            end


            if ImGui.BeginTabItem('Settings/Utils') then
                local res1, res2 = ImGui.SliderFloat('Fetch Interval (sec)##BotFetchDelay', botUI.botFetchDelay, 0.1, 5.0, '%.1f')
                if type(res1) == 'boolean' then
                    if res1 then
                        botUI.botFetchDelay = math.max(0.1, tonumber(res2) or botUI.botFetchDelay)
                        botUI._botInventoryLastAttempt = {}
                        enqueueTask(botUI._processBotInventoryQueue)
                    end
                else
                    local newDelay = tonumber(res1) or botUI.botFetchDelay
                    if math.abs(newDelay - botUI.botFetchDelay) > 0.0001 then
                        botUI.botFetchDelay = math.max(0.1, newDelay)
                        botUI._botInventoryLastAttempt = {}
                        botUI._botInventoryFetchQueue = {}
                        botUI._botInventoryFetchSet = {}
                    end
                end
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Time to wait between bot inventory requests')
                end

                local sRes1, sRes2 = ImGui.SliderFloat('Spawn Delay (sec)##BotSpawnDelay', botUI.botSpawnDelay, 0.1, 5.0, '%.1f')
                if type(sRes1) == 'boolean' then
                    if sRes1 then
                        botUI.botSpawnDelay = math.max(0.1, tonumber(sRes2) or botUI.botSpawnDelay)
                    end
                else
                    local newSpawn = tonumber(sRes1) or botUI.botSpawnDelay
                    if math.abs(newSpawn - botUI.botSpawnDelay) > 0.0001 then
                        botUI.botSpawnDelay = math.max(0.1, newSpawn)
                    end
                end
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Delay after spawning before targeting the bot')
                end

                local tRes1, tRes2 = ImGui.SliderFloat('Target Delay (sec)##BotTargetDelay', botUI.botTargetDelay, 0.1, 5.0, '%.1f')
                if type(tRes1) == 'boolean' then
                    if tRes1 then
                        botUI.botTargetDelay = math.max(0.1, tonumber(tRes2) or botUI.botTargetDelay)
                    end
                else
                    local newTarget = tonumber(tRes1) or botUI.botTargetDelay
                    if math.abs(newTarget - botUI.botTargetDelay) > 0.0001 then
                        botUI.botTargetDelay = math.max(0.1, newTarget)
                    end
                end
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Delay after targeting before requesting inventory')
                end
                
                ImGui.Separator()
                ImGui.Text('Bot Failure Management')
                
                -- Failure settings
                local maxRes1, maxRes2 = ImGui.SliderInt('Max Failures##MaxFailures', botUI._maxFailures, 1, 10)
                if type(maxRes1) == 'boolean' then
                    if maxRes1 then
                        botUI._maxFailures = math.max(1, tonumber(maxRes2) or botUI._maxFailures)
                    end
                else
                    local newMax = tonumber(maxRes1) or botUI._maxFailures
                    if newMax ~= botUI._maxFailures then
                        botUI._maxFailures = math.max(1, newMax)
                    end
                end
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Maximum failures before skipping a bot')
                end
                
                local timeRes1, timeRes2 = ImGui.SliderInt('Skip Timeout (sec)##SkipTimeout', botUI._failureTimeout, 60, 1800)
                if type(timeRes1) == 'boolean' then
                    if timeRes1 then
                        botUI._failureTimeout = math.max(60, tonumber(timeRes2) or botUI._failureTimeout)
                    end
                else
                    local newTimeout = tonumber(timeRes1) or botUI._failureTimeout
                    if newTimeout ~= botUI._failureTimeout then
                        botUI._failureTimeout = math.max(60, newTimeout)
                    end
                end
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Seconds to skip a failed bot before allowing retry')
                end

                ImGui.Separator()
                ImGui.Text('Upgrade Window')
                local closePref = botUI.closeUpgradeWindowOnSwap and true or false
                local newClosePref, closeChanged = ImGui.Checkbox('Close upgrade window after swap##UpgradeClose', closePref)
                if closeChanged then
                    botUI.closeUpgradeWindowOnSwap = newClosePref and true or false
                    if upgrade and upgrade.set_close_window_on_swap then
                        upgrade.set_close_window_on_swap(botUI.closeUpgradeWindowOnSwap)
                    end
                end
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Automatically close the upgrade comparison window after a successful swap')
                end

                ImGui.Separator()
                ImGui.Text('Viewer:')
                ImGui.SameLine()
                do
                    local cur = botUI.viewerShowClassInSelector and true or false
                    local newVal, pressed = ImGui.Checkbox('Show class only in selector##viewer_class_toggle', cur)
                    if pressed then botUI.viewerShowClassInSelector = newVal and true or false end
                end
                do
                    local cur = botUI.viewerAppendClassAbbrevInSelector and true or false
                    local newVal, pressed = ImGui.Checkbox('Append short class to name in selector##viewer_class_append', cur)
                    if pressed then botUI.viewerAppendClassAbbrevInSelector = newVal and true or false end
                end
                
                ImGui.Separator()
                ImGui.Text('UI Components')
                
                -- Raid HUD toggle
                if ImGui.Button('Toggle Raid HUD') then
                    if raid_hud and raid_hud.toggle then
                        raid_hud.toggle()
                    end
                end
                if ImGui.IsItemHovered() then
                    local status = (raid_hud and raid_hud.is_visible and raid_hud.is_visible()) and 'visible' or 'hidden'
                    ImGui.SetTooltip(string.format('Toggle raid HUD floating window (currently %s)', status))
                end
                
                -- Bot Controls toggle button
                ImGui.SameLine()
                if ImGui.Button('Toggle Bot Controls') then
                    if bot_controls and bot_controls.toggle then
                        bot_controls.toggle()
                    end
                end
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Toggle bot controls window')
                end
                
                -- Show skipped bots
                local skippedBots = botUI.getSkippedBots()
                if #skippedBots > 0 then
                    ImGui.Spacing()
                    ImGui.Text(string.format('Skipped Bots (%d):', #skippedBots))
                    
                    if ImGui.BeginTable('SkippedBotsTable', 4,
                            ImGuiTableFlags.Borders + ImGuiTableFlags.RowBg + ImGuiTableFlags.Sortable) then
                        ImGui.TableSetupColumn('Bot Name', ImGuiTableColumnFlags.WidthStretch)
                        ImGui.TableSetupColumn('Failures', ImGuiTableColumnFlags.WidthFixed, 60)
                        ImGui.TableSetupColumn('Time Left', ImGuiTableColumnFlags.WidthFixed, 80)
                        ImGui.TableSetupColumn('Action', ImGuiTableColumnFlags.WidthFixed, 80)
                        ImGui.TableHeadersRow()

                        local sortSpecs = ImGui.TableGetSortSpecs()
                        applyTableSort(skippedBots, sortSpecs, {
                            [1] = function(row) return row.name or '' end,
                            [2] = function(row) return row.failures or 0 end,
                            [3] = function(row) return row.remaining or 0 end,
                        })
                        
                        for i, bot in ipairs(skippedBots) do
                            ImGui.TableNextRow()
                            
                            ImGui.TableNextColumn()
                            ImGui.Text(bot.name)
                            
                            ImGui.TableNextColumn()
                            ImGui.Text(tostring(bot.failures))
                            
                            ImGui.TableNextColumn()
                            if bot.remaining > 0 then
                                local minutes = math.floor(bot.remaining / 60)
                                local seconds = bot.remaining % 60
                                ImGui.Text(string.format('%dm %ds', minutes, seconds))
                            else
                                ImGui.TextColored(0.0, 0.9, 0.0, 1.0, 'Ready')
                            end
                            
                            ImGui.TableNextColumn()
                            if ImGui.SmallButton('Retry##' .. bot.name) then
                                botUI.unskipBot(bot.name)
                            end
                        end
                        
                        ImGui.EndTable()
                    end
                    
                    if ImGui.Button('Clear All Skipped Bots') then
                        botUI.clearAllSkippedBots()
                    end
                else
                    ImGui.Text('No bots currently skipped')
                end

                -- Utils: Export Data
                ImGui.Separator()
                ImGui.Text('Export Data')
                ImGui.SameLine()
                if ImGui.Button('Export JSON') then
                    if bot_inventory and bot_inventory.exportBotInventories then
                        local ok, result = bot_inventory.exportBotInventories('json')
                        if ok then
                            botUI.lastExportWasSuccess = true
                            botUI.lastExportMessage = string.format('Exported JSON to %s', tostring(result))
                            printf('[EmuBot] Exported JSON inventory snapshot to %s', tostring(result))
                        else
                            botUI.lastExportWasSuccess = false
                            botUI.lastExportMessage = string.format('Export failed: %s', tostring(result))
                            printf('[EmuBot] Export to JSON failed: %s', tostring(result))
                        end
                    end
                end
                ImGui.SameLine()
                if ImGui.Button('Export CSV') then
                    if bot_inventory and bot_inventory.exportBotInventories then
                        local ok, result = bot_inventory.exportBotInventories('csv')
                        if ok then
                            botUI.lastExportWasSuccess = true
                            botUI.lastExportMessage = string.format('Exported CSV to %s', tostring(result))
                            printf('[EmuBot] Exported CSV inventory snapshot to %s', tostring(result))
                        else
                            botUI.lastExportWasSuccess = false
                            botUI.lastExportMessage = string.format('Export failed: %s', tostring(result))
                            printf('[EmuBot] Export to CSV failed: %s', tostring(result))
                        end
                    end
                end
                if botUI.lastExportMessage then
                    local message = botUI.lastExportMessage
                    if botUI.lastExportWasSuccess then
                        ImGui.Text(message)
                    else
                        ImGui.TextWrapped(message)
                    end
                end

                ImGui.Spacing()
                ImGui.Separator()
                ImGui.TextColored(0.9, 0.3, 0.3, 1.0, 'Danger Zone')
                ImGui.SameLine()
                ImGui.Text(' (server-wide data)')

                ImGui.PushStyleColor(ImGuiCol.Button, 0.8, 0.2, 0.2, 0.95)
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.85, 0.25, 0.25, 1.0)
                ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.7, 0.15, 0.15, 1.0)
                if ImGui.Button('Purge Database##EmuBot', ImVec2(160, 0)) then
                    ImGui.OpenPopup('EmuBotPurgeConfirm')
                end
                ImGui.PopStyleColor(3)
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip('Drops all stored EmuBot data (bots, inventories, groups) for this server.')
                end

                if botUI.lastPurgeMessage then
                    if botUI.lastPurgeWasSuccess then
                        ImGui.Text(botUI.lastPurgeMessage)
                    else
                        ImGui.TextColored(1.0, 0.4, 0.4, 1.0, botUI.lastPurgeMessage)
                    end
                end

                if ImGui.BeginPopupModal('EmuBotPurgeConfirm', true, ImGuiWindowFlags.AlwaysAutoResize) then
                    ImGui.TextWrapped('This will drop all EmuBot SQLite tables for this server and rebuild them empty. All cached inventories, groups, and item data will be lost. Are you sure you want to continue?')
                    ImGui.Spacing()
                    ImGui.Separator()
                    ImGui.Spacing()

                    ImGui.PushStyleColor(ImGuiCol.Button, 0.8, 0.2, 0.2, 0.95)
                    ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.85, 0.25, 0.25, 1.0)
                    ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.7, 0.15, 0.15, 1.0)
                    local confirm = ImGui.Button('Confirm Purge##EmuBot', ImVec2(150, 32))
                    ImGui.PopStyleColor(3)

                    if confirm then
                        local ok, err = performDatabasePurge()
                        if ok then
                            botUI.lastPurgeWasSuccess = true
                            botUI.lastPurgeMessage = 'Database purged successfully. Caches reset.'
                        else
                            botUI.lastPurgeWasSuccess = false
                            botUI.lastPurgeMessage = string.format('Database purge failed: %s', tostring(err))
                        end
                        ImGui.CloseCurrentPopup()
                    end

                    ImGui.SameLine()
                    if ImGui.Button('Cancel##EmuBot', ImVec2(150, 32)) then
                        ImGui.CloseCurrentPopup()
                    end

                    ImGui.EndPopup()
                end

                ImGui.EndTabItem()
            end

            ImGui.EndTabBar()
        end

        ImGui.Spacing()
        ImGui.Text(string.format('Items: %d', #equippedItems))
        local withLinks = 0
        local withoutLinks = 0
        for _, item in ipairs(equippedItems or {}) do
            if item.itemlink and item.itemlink ~= '' then
                withLinks = withLinks + 1
            else
                withoutLinks = withoutLinks + 1
            end
        end

        ImGui.SameLine()
        ImGui.Text(string.format('Links: %d/%d', withLinks, withLinks + withoutLinks))
    end

    -- Show the scan all confirmation popup
    ImGui.SetNextWindowSize(ImVec2(500, 200), ImGuiCond.Always)
    if ImGui.BeginPopupModal('Scan All Bots##ScanAllConfirm', true, ImGuiWindowFlags.AlwaysAutoResize) then
        ImGui.TextWrapped('Do you have more bots created than you can spawn? We can automatically camp each bot after scanning, so that you can scan every bot you\'ve created. Would you like us to do so?')
        
        ImGui.Spacing()
        ImGui.Separator()
        ImGui.Spacing()
        
        if ImGui.Button('YES', ImVec2(120, 30)) then
            -- Start scan with camping enabled (refresh bot list first)
            botUI._startScanAllAfterRefresh(false)
            ImGui.CloseCurrentPopup()
        end
        
        ImGui.SameLine()
        
        if ImGui.Button('NO', ImVec2(120, 30)) then
            -- Start scan with camping disabled (refresh bot list first)
            botUI._startScanAllAfterRefresh(true)
            ImGui.CloseCurrentPopup()
        end
        
        ImGui.SameLine()
        
        if ImGui.Button('Cancel', ImVec2(120, 30)) then
            ImGui.CloseCurrentPopup()
        end
        
        ImGui.EndPopup()
    end

    ImGui.End()
    EmuBot_PopRounding()
end

local function drawFloatingToggle()
    if not botUI.showFloatingToggle then return end

    -- Position and minimal floating window
    ImGui.SetNextWindowPos(ImVec2(botUI.floatingPosX, botUI.floatingPosY), ImGuiCond.FirstUseEver)
    ImGui.SetNextWindowSize(ImVec2(botUI.floatingButtonSize + 8, botUI.floatingButtonSize + 8), ImGuiCond.FirstUseEver)

    local flags = bit32.bor(
        ImGuiWindowFlags.NoTitleBar,
        ImGuiWindowFlags.NoResize,
        ImGuiWindowFlags.NoScrollbar,
        ImGuiWindowFlags.NoScrollWithMouse,
        ImGuiWindowFlags.NoCollapse,
        ImGuiWindowFlags.AlwaysAutoResize,
        ImGuiWindowFlags.NoBackground,
        ImGuiWindowFlags.NoDecoration
    )

    ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, 4, 4)
    ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.WindowBorderSize, 1)
    ImGui.PushStyleColor(ImGuiCol.WindowBg, 0.1, 0.1, 0.1, 0.85)
    ImGui.PushStyleColor(ImGuiCol.Border, 0.4, 0.4, 0.4, 0.8)

    if ImGui.Begin('EmuBotToggle', true, flags) then
        -- Track position as it moves
        local pos = ImGui.GetWindowPosVec()
        if pos then
            botUI.floatingPosX = pos.x
            botUI.floatingPosY = pos.y
        end

        -- Choose colors based on current visibility (toggle-style)
        if botUI.showWindow then
            -- Open state: orange-ish
            ImGui.PushStyleColor(ImGuiCol.Button, 0.85, 0.55, 0.15, 0.95)
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.95, 0.65, 0.25, 1.0)
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.75, 0.45, 0.10, 1.0)
        else
            -- Closed state: green
            ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.6, 0.2, 0.9)
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.25, 0.7, 0.25, 1.0)
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.15, 0.5, 0.15, 1.0)
        end

        -- Rounded button corners
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, math.min(12, botUI.floatingButtonSize * 0.4))

        if ImGui.Button('EB', ImVec2(botUI.floatingButtonSize, botUI.floatingButtonSize)) then
            botUI.showWindow = not botUI.showWindow
        end
        if ImGui.IsItemClicked(ImGuiMouseButton.Right) then if bot_controls and bot_controls.toggle then bot_controls.toggle() end end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip(string.format('Toggle EmuBot (%s) | Right-click: Bot Controls', botUI.showWindow and 'Open' or 'Closed'))
        end

        ImGui.PopStyleVar(1)
        ImGui.PopStyleColor(3)
    end
    ImGui.End()
    ImGui.PopStyleColor(2)
    ImGui.PopStyleVar(3)
end

local function drawUpgradeQuickButton()
    if not botUI.showUpgradeFloating then return end

    -- Position and minimal floating window for ^iu
    ImGui.SetNextWindowPos(ImVec2(botUI.upgradePosX, botUI.upgradePosY), ImGuiCond.FirstUseEver)
    ImGui.SetNextWindowSize(ImVec2(botUI.upgradeButtonSize + 8, botUI.upgradeButtonSize + 8), ImGuiCond.FirstUseEver)

    local flags = bit32.bor(
        ImGuiWindowFlags.NoTitleBar,
        ImGuiWindowFlags.NoResize,
        ImGuiWindowFlags.NoScrollbar,
        ImGuiWindowFlags.NoScrollWithMouse,
        ImGuiWindowFlags.NoCollapse,
        ImGuiWindowFlags.AlwaysAutoResize,
        ImGuiWindowFlags.NoBackground,
        ImGuiWindowFlags.NoDecoration
    )

    ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, 4, 4)
    ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.WindowBorderSize, 1)
    ImGui.PushStyleColor(ImGuiCol.WindowBg, 0.1, 0.1, 0.1, 0.85)
    ImGui.PushStyleColor(ImGuiCol.Border, 0.4, 0.4, 0.4, 0.8)

    if ImGui.Begin('EmuBotIU', true, flags) then
        -- Track position as it moves
        local pos = ImGui.GetWindowPosVec()
        if pos then
            botUI.upgradePosX = pos.x
            botUI.upgradePosY = pos.y
        end

        -- Use color indicating cursor status
        if mq.TLO.Cursor() then
            -- Cursor has item: accent blue
            ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.5, 0.9, 0.9)
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.3, 0.6, 1.0, 1.0)
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.15, 0.45, 0.85, 1.0)
        else
            -- No item: gray
            ImGui.PushStyleColor(ImGuiCol.Button, 0.4, 0.4, 0.4, 0.9)
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.5, 0.5, 0.5, 1.0)
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.35, 0.35, 0.35, 1.0)
        end

        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, math.min(12, botUI.upgradeButtonSize * 0.4))

        if ImGui.Button('IU', ImVec2(botUI.upgradeButtonSize, botUI.upgradeButtonSize)) then
            if upgrade and upgrade.poll_iu then
                upgrade.poll_iu()
            else
                mq.cmd('/say ^iu')
            end
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Poll bots for upgrades (^iu)')
        end

        ImGui.PopStyleVar(1)
        ImGui.PopStyleColor(3)
    end
    ImGui.End()
    ImGui.PopStyleColor(2)
    ImGui.PopStyleVar(3)
end


function botUI.render()
    -- Draw floating toggles even if main window is closed
    drawFloatingToggle()
    drawUpgradeQuickButton()
    if bot_controls and bot_controls.draw then bot_controls.draw() end
    -- Draw upgrade comparison overlay window even if tab is not active
    if upgrade and upgrade.draw_compare_window then upgrade.draw_compare_window() end
    -- Draw raid HUD if enabled
    if raid_hud and raid_hud.draw then raid_hud.draw() end
    
    botUI.drawBotInventoryWindow()
    
    -- Draw the local comparison window if needed (separate window)
    botUI.drawLocalComparisonWindow()
end

-- Bind a slash command to reopen the EmuBot UI
mq.bind("/emubot", function(...)
    local args = {...}
    if #args > 0 then
        local cmd = tostring(args[1] or ''):lower()
        if cmd == 'on' or cmd == 'show' or cmd == 'open' then
            botUI.showWindow = true
            printf('[EmuBot] Window opened')
        elseif cmd == 'off' or cmd == 'hide' or cmd == 'close' then
            botUI.showWindow = false
            printf('[EmuBot] Window closed')
        elseif cmd == 'skip' and args[2] then
            -- Skip a specific bot
            local botName = tostring(args[2])
            local reason = args[3] and tostring(args[3]) or 'Manual skip'
            if botUI.skipBot(botName, reason) then
                printf('[EmuBot] Skipped bot: %s', botName)
            else
                printf('[EmuBot] Failed to skip bot: %s', botName)
            end
        elseif cmd == 'unskip' and args[2] then
            -- Unskip a specific bot
            local botName = tostring(args[2])
            if botUI.unskipBot(botName) then
                printf('[EmuBot] Unskipped bot: %s', botName)
            else
                printf('[EmuBot] Bot %s was not in skip list', botName)
            end
        elseif cmd == 'clearskipped' or cmd == 'clearskip' then
            -- Clear all skipped bots
            local count = botUI.clearAllSkippedBots()
            printf('[EmuBot] Cleared %d bots from skip list', count)
        elseif cmd == 'listskipped' or cmd == 'skipped' then
            -- List skipped bots
            local skipped = botUI.getSkippedBots()
            if #skipped > 0 then
                printf('[EmuBot] Skipped bots (%d):', #skipped)
                for _, bot in ipairs(skipped) do
                    local timeStr = ''
                    if bot.remaining > 0 then
                        local minutes = math.floor(bot.remaining / 60)
                        local seconds = bot.remaining % 60
                        timeStr = string.format(' (%dm %ds remaining)', minutes, seconds)
                    else
                        timeStr = ' (ready for retry)'
                    end
                    printf('  %s - %d failures%s', bot.name, bot.failures, timeStr)
                end
            else
                printf('[EmuBot] No bots currently skipped')
            end
        elseif cmd == 'testslot' and args[2] and args[3] then
            -- Test item slot compatibility
            local itemName = tostring(args[2])
            local slotId = tonumber(args[3])
            local className = args[4] and tostring(args[4]) or nil
            if slotId then
                botUI.debugItemSlotCompatibility(itemName, slotId, className)
            else
                printf('[EmuBot] Invalid slot ID: %s', tostring(args[3]))
            end
        elseif cmd == 'raidhud' then
            -- Toggle raid HUD
            if raid_hud and raid_hud.toggle then
                raid_hud.toggle()
                printf('[EmuBot] Raid HUD %s', raid_hud.is_visible() and 'enabled' or 'disabled')
            else
                printf('[EmuBot] Raid HUD module not available')
            end
        elseif cmd == 'help' then
            printf('[EmuBot] Available commands:')
            printf('  /emubot [on|off] - Open/close the UI')
            printf('  /emubot skip <botname> [reason] - Skip a bot')
            printf('  /emubot unskip <botname> - Remove bot from skip list')
            printf('  /emubot clearskipped - Clear all skipped bots')
            printf('  /emubot listskipped - Show currently skipped bots')
            printf('  /emubot testslot <itemname> <slotid> [class] - Test item/slot/class compatibility')
            printf('  /emubot raidhud - Toggle raid HUD')
            printf('  /emubot help - Show this help')
        else
            botUI.showWindow = not botUI.showWindow
            printf('[EmuBot] Window %s', botUI.showWindow and 'opened' or 'closed')
        end
    else
        botUI.showWindow = not botUI.showWindow
        printf('[EmuBot] Window %s', botUI.showWindow and 'opened' or 'closed')
    end
end)

mq.bind("/emubotbutton", function(...)
    botUI.showFloatingToggle = not botUI.showFloatingToggle
    printf('[EmuBot] Floating toggle %s', botUI.showFloatingToggle and 'enabled' or 'disabled')
end)

mq.bind("/emubotiu", function(...)
    botUI.showUpgradeFloating = not botUI.showUpgradeFloating
    printf('[EmuBot] ^iu quick button %s', botUI.showUpgradeFloating and 'enabled' or 'disabled')
end)

local function main()
    if not bot_inventory.init() then
        print('[EmuBot] Failed to initialize bot inventory system')
        return
    end
    
    -- Connect skip system to bot inventory module
    bot_inventory.skipCheckFunction = function(botName)
        return botUI._skippedBots[botName] ~= nil
    end
    
    bot_inventory.onBotFailure = function(botName, reason)
        local failCount = (botUI._botFailureCount[botName] or 0) + 1
        botUI._botFailureCount[botName] = failCount
        
        printf('[EmuBot] Bot %s failed: %s (attempt %d/%d)', botName, reason, failCount, botUI._maxFailures)
        
        if failCount >= botUI._maxFailures then
            printf('[EmuBot] Bot %s exceeded max failures, skipping for %d seconds', botName, botUI._failureTimeout)
            botUI._skippedBots[botName] = os.time()
            
            -- Remove from current queues
            for i = #botUI._botInventoryFetchQueue, 1, -1 do
                if botUI._botInventoryFetchQueue[i] == botName then
                    table.remove(botUI._botInventoryFetchQueue, i)
                end
            end
            botUI._botInventoryFetchSet[botName] = nil
        end
    end
    
    -- Connect mismatch detection to item scanning system
    bot_inventory.onMismatchDetected = function(item, botName, reason)
        if botUI.enqueueItemScan then
            botUI.enqueueItemScan(item, botName)
            botUI._autoScannedItems = botUI._autoScannedItems + 1
            printf('[EmuBot] Auto-scanning %s from %s due to: %s', item.name or 'unknown item', botName, reason)
        end
    end

    -- Kick off a bot list refresh on startup so the dropdown populates.
    refreshBotList()

    -- Initialize optional modules
    if bot_groups and bot_groups.init then bot_groups.init() end
    if raid_manager and raid_manager.set_enqueue then raid_manager.set_enqueue(enqueueTask) end
    if raid_manager and raid_manager.init then raid_manager.init() end
    if upgrade and upgrade.init then upgrade.init() end
    if raid_hud and raid_hud.init then raid_hud.init() end

    -- Start the Bot HotBar floating UI
    if commandsui and commandsui.start then commandsui.start() end

    mq.imgui.init('EmuBot', function()
        botUI.render()
    end)

    while true do
        mq.doevents()
        bot_inventory.process()
        bot_groups.process_invitations()
        processDeferredTasks()
        
        -- Process delayed refresh after bot creation
        if _G.EmuBotDelayedRefresh and not _G.EmuBotDelayedRefresh.executed then
            local elapsed = os.time() - _G.EmuBotDelayedRefresh.scheduled
            if elapsed >= _G.EmuBotDelayedRefresh.delay then
                if bot_inventory and bot_inventory.refreshBotList then
                    bot_inventory.refreshBotList()
                end
                _G.EmuBotDelayedRefresh.executed = true
                _G.EmuBotDelayedRefresh = nil
            end
        end
        
        mq.delay(50)
    end
end

-- Cleanup function for when script terminates
local function cleanup()
    printf('[EmuBot] Shutting down...')
    if raid_hud and raid_hud.cleanup then raid_hud.cleanup() end
    if bot_controls and bot_controls.cleanup then bot_controls.cleanup() end
end

-- Set up cleanup on script termination
mq.bind('/lua stop EmuBot', cleanup)

local status, result = pcall(main)
if not status then
    printf('[EmuBot] Error in main loop: %s', tostring(result))
    cleanup()
else
    cleanup()
end

-- Expose a simple global toggle to enable DB debug logging from chat:
-- Usage: /lua eval EmuBotDBDebug(true)  or  /lua eval EmuBotDBDebug(false)
_G.EmuBotDBDebug = function(enabled)
    if db and db.set_debug then db.set_debug(enabled) end
end
