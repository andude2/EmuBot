-- bot_inventory.lua
local mq = require("mq")
local json = require("dkjson")
local db = require('EmuBot.modules.db')

local BotInventory = {}
BotInventory.bot_inventories = {}
BotInventory.pending_requests = {}
BotInventory.current_bot_request = nil
BotInventory.cached_bot_list = {}
BotInventory.refreshing_bot_list = false
BotInventory.bot_list_start_time = nil
BotInventory.bot_request_start_time = nil
BotInventory.refresh_all_pending = false
BotInventory.spawn_issued_time = nil
BotInventory.target_issued_time = nil
BotInventory.bot_request_phase = 0
BotInventory.bot_list_capture_set = {}
BotInventory.invlist_issued_time = nil
BotInventory._resources_dir = nil
BotInventory._capture_count = {}
BotInventory._owner = nil
BotInventory._events_registered = false
BotInventory._itemStatCache = {}
BotInventory.active_capture_buffers = {}
BotInventory.capture_expected_slots = 23
BotInventory.capture_settle_delay = 0.2
BotInventory.capture_timeout_seconds = 4
BotInventory.capture_slot_tolerance = 1 -- allow finalize within one missing slot (berserkers lack secondary)

local function normalizePathSeparators(path)
    return path and path:gsub('\\\\', '/') or nil
end

local function trimTrailingSlash(path)
    if not path then return nil end
    return path:gsub('/+$', '')
end

local function detectResourcesDir()
    if BotInventory._resources_dir ~= nil then
        return BotInventory._resources_dir
    end

    local resolved

    if mq and mq.TLO and mq.TLO.MacroQuest and mq.TLO.MacroQuest.Path then
        local ok, result = pcall(function()
            local tlo = mq.TLO.MacroQuest.Path('Resources')
            if tlo and tlo() and tlo() ~= '' then
                return tlo()
            end
            return nil
        end)
        if ok and result and result ~= '' then
            resolved = result
        end
    end

    if (not resolved) and mq and mq.luaDir then
        local ok, result = pcall(function()
            if type(mq.luaDir) == 'function' then
                return mq.luaDir()
            end
            return mq.luaDir
        end)
        if ok and result and result ~= '' then
            local normalized = trimTrailingSlash(normalizePathSeparators(tostring(result)))
            if normalized then
                local root = normalized:match('^(.*)/lua$')
                if root and root ~= '' then
                    resolved = root .. '/Resources'
                end
            end
        end
    end

    if not resolved then
        local info = debug.getinfo(detectResourcesDir, 'S')
        local source = info and info.source
        if source and source:sub(1, 1) == '@' then
            local normalized = normalizePathSeparators(source:sub(2))
            if normalized then
                local root = normalized:match('^(.*)/lua/')
                if root and root ~= '' then
                    resolved = root .. '/Resources'
                end
            end
        end
    end

    if resolved then
        resolved = trimTrailingSlash(normalizePathSeparators(resolved))
    end

    BotInventory._resources_dir = resolved
    return BotInventory._resources_dir
end

-- Convert itemID to a clickable web URL based on the selected export option
local function createItemURL(itemID)
    if not itemID or itemID == 0 then return "" end

    -- Determine server to select appropriate URL
    local serverName = ""
    if mq and mq.TLO and mq.TLO.EverQuest and mq.TLO.EverQuest.Server then
        local ok, server = pcall(function() return mq.TLO.EverQuest.Server() end)
        if ok and server then
            serverName = tostring(server)
        end
    end

    -- Return URL based on server
    if serverName == "Karana" then
        return string.format("https://karanaeq.com/Alla/?a=item&id=%s", tostring(itemID))
    elseif serverName == "Shadowed Eclipse" then
        return string.format("http://shadowedeclipse.com/?a=item&id=%s", tostring(itemID))
    else
        -- For other servers, return empty string to skip hyperlinks
        return ""
    end
end

local function resolveCurrentOwner()
    if mq and mq.TLO and mq.TLO.Me then
        local ok, name = pcall(function()
            if mq.TLO.Me.CleanName and mq.TLO.Me.CleanName() then return mq.TLO.Me.CleanName() end
            if mq.TLO.Me.Name and mq.TLO.Me.Name() then return mq.TLO.Me.Name() end
            return nil
        end)
        if ok and name and name ~= '' then
            return tostring(name)
        end
    end
    return 'unknown'
end

local function resetStateForOwner(owner)
    BotInventory.bot_inventories = {}
    BotInventory.pending_requests = {}
    BotInventory.current_bot_request = nil
    BotInventory.cached_bot_list = {}
    BotInventory.refreshing_bot_list = false
    BotInventory.bot_list_start_time = nil
    BotInventory.bot_request_start_time = nil
    BotInventory.refresh_all_pending = false
    BotInventory.spawn_issued_time = nil
    BotInventory.target_issued_time = nil
    BotInventory.bot_request_phase = 0
    BotInventory.bot_list_capture_set = {}
    BotInventory.invlist_issued_time = nil
    BotInventory._capture_count = {}
    BotInventory._owner = owner
    BotInventory._itemStatCache = {}
    BotInventory.active_capture_buffers = {}
end

local function ensureBotInventoryRecord(botName)
    if not botName or botName == '' then return nil end
    local owner = BotInventory._owner or resolveCurrentOwner()
    local record = BotInventory.bot_inventories[botName]
    if not record then
        record = {
            name = botName,
            equipped = {},
            bags = {},
            bank = {},
            owner = owner,
        }
        BotInventory.bot_inventories[botName] = record
    end
    record.owner = owner
    return record
end

local function cloneItemState(item)
    if not item then return nil end
    local copy = {}
    for k, v in pairs(item) do
        copy[k] = v
    end
    return copy
end

local function cloneInventoryState(data)
    if not data then return nil end
    local copy = {
        name = data.name,
        owner = data.owner,
        bags = data.bags,
        bank = data.bank,
        equipped = {},
    }
    for _, item in ipairs(data.equipped or {}) do
        table.insert(copy.equipped, cloneItemState(item))
    end
    return copy
end

local function beginCaptureBuffer(botName)
    if not botName or botName == '' then return nil end
    local buffer = {
        items_by_slot = {},
        slots_seen = {},
        processed_slots = 0,
        total_lines = 0,
        last_line_time = nil,
    }
    BotInventory.active_capture_buffers[botName] = buffer
    return buffer
end

local function getCaptureBuffer(botName)
    if not botName or botName == '' then return nil end
    return BotInventory.active_capture_buffers[botName]
end

local function resetActiveRequestState(botName)
    if botName and botName ~= '' then
        BotInventory._capture_count[botName] = 0
        BotInventory.active_capture_buffers[botName] = nil
    end
    BotInventory.current_bot_request = nil
    BotInventory.bot_request_start_time = nil
    BotInventory.bot_request_phase = 0
    BotInventory.spawn_issued_time = nil
    BotInventory.target_issued_time = nil
    BotInventory.invlist_issued_time = nil
end

local function buildEquippedFromBuffer(buffer)
    if not buffer or not buffer.items_by_slot then return {} end
    local orderedSlots = {}
    for slotId in pairs(buffer.items_by_slot) do
        table.insert(orderedSlots, slotId)
    end
    table.sort(orderedSlots, function(a, b)
        local numA, numB = tonumber(a), tonumber(b)
        if numA and numB then return numA < numB end
        if numA then return true end
        if numB then return false end
        return tostring(a) < tostring(b)
    end)
    local equipped = {}
    for _, slotId in ipairs(orderedSlots) do
        local item = buffer.items_by_slot[slotId]
        if item then
            table.insert(equipped, item)
        end
    end
    return equipped
end

local function finalizeBotInventoryCapture(botName, buffer)
    buffer = buffer or getCaptureBuffer(botName)
    if not botName or botName == '' or not buffer then return false end

    local record = ensureBotInventoryRecord(botName)
    if not record then return false end

    local oldData = cloneInventoryState(record)
    record.owner = BotInventory._owner or resolveCurrentOwner()
    record.equipped = buildEquippedFromBuffer(buffer)

    if oldData and BotInventory.compareInventoryData then
        local mismatches = BotInventory.compareInventoryData(botName, oldData, record) or {}
        if #mismatches > 0 then
            print(string.format("[BotInventory] Detected %d mismatched item(s) for %s, queueing for scan",
                #mismatches, botName))
            if BotInventory.onMismatchDetected then
                for _, mismatch in ipairs(mismatches) do
                    print(string.format("[BotInventory] Queueing %s (slot %s) for scan: %s",
                        mismatch.item.name or "unknown",
                        tostring(mismatch.slotId),
                        mismatch.reason))
                    BotInventory.onMismatchDetected(mismatch.item, botName, mismatch.reason)
                end
            end
        end
    end

    local meta = BotInventory.bot_list_capture_set and BotInventory.bot_list_capture_set[botName] or nil
    local ok, err = db.save_bot_inventory(botName, record, meta)
    if not ok then
        print(string.format("[BotInventory][DB] Failed to save inventory for %s: %s", botName, tostring(err)))
    end

    resetActiveRequestState(botName)
    return true
end

local function failActiveRequest(botName, reason)
    if botName then
        print(string.format("[BotInventory] %s", reason or string.format("Request failed for %s", botName)))
    else
        print(string.format("[BotInventory] %s", reason or "Request failed"))
    end
    if BotInventory.onBotFailure and botName then
        BotInventory.onBotFailure(botName, reason or "Request failed")
    end
    resetActiveRequestState(botName)
end

local function cloneItemForExport(item)
    if not item then return nil end

    local copy = {
        name = item.name,
        slotid = item.slotid,
        slotname = item.slotname,
        itemID = item.itemID,
        icon = item.icon,
        stackSize = item.stackSize,
        charges = item.charges,
        ac = item.ac,
        hp = item.hp,
        mana = item.mana,
        damage = item.damage,
        delay = item.delay,
        qty = item.qty,
        nodrop = item.nodrop,
    }

    -- Replace in-game itemlink with URL based on the server if we have an itemID
    if item.itemID and tonumber(item.itemID) and tonumber(item.itemID) > 0 then
        copy.itemlink = createItemURL(item.itemID)
    elseif type(item.itemlink) == "string" then
        copy.itemlink = item.itemlink -- Fallback to original link if no itemID
    end

    if type(item.rawline) == "string" then
        copy.rawline = item.rawline
    end

    return copy
end

local function copyItemListForExport(source)
    local result = {}
    if not source then return result end

    for _, item in ipairs(source) do
        local sanitized = cloneItemForExport(item)
        if sanitized then
            table.insert(result, sanitized)
        end
    end

    return result
end

local function buildExportSnapshot()
    local snapshot = {}

    for botName, data in pairs(BotInventory.bot_inventories or {}) do
        local entry = {
            name = data and data.name or botName,
            equipped = copyItemListForExport(data and data.equipped),
            bags = copyItemListForExport(data and data.bags),
            bank = copyItemListForExport(data and data.bank),
        }

        snapshot[#snapshot + 1] = entry
    end

    table.sort(snapshot, function(a, b)
        local nameA = (a and a.name) or ""
        local nameB = (b and b.name) or ""
        return nameA:lower() < nameB:lower()
    end)

    return snapshot
end

local function targetBotByName(botName)
    if not botName or botName == "" then return end

    local spawnLookup = mq.TLO.Spawn(string.format("= %s", botName))
    local ok, spawnId = pcall(function()
        return spawnLookup and spawnLookup.ID and spawnLookup.ID()
    end)

    if ok and spawnId and spawnId > 0 then
        mq.cmdf("/target id %d", spawnId)
    else
        mq.cmdf('/target "%s"', botName)
    end
end

local function defaultExportFilename(format)
    local ext = (format and format:lower()) or "json"
    local timestamp = os.date("%Y%m%d_%H%M%S")
    return string.format("bot_inventories_%s.%s", timestamp, ext)
end

local function resolveExportPath(format, customPath)
    if customPath and customPath ~= "" then return customPath end

    local resourcesDir = detectResourcesDir()
    if resourcesDir and resourcesDir ~= "" then
        return string.format("%s/%s", resourcesDir, defaultExportFilename(format))
    end

    return defaultExportFilename(format)
end

local function writeFile(path, contents)
    local file, err = io.open(path, "w")
    if not file then
        return false, err or "Unable to open file"
    end

    file:write(contents or "")
    file:close()
    return true
end

local function encodeSnapshotAsJSON(snapshot)
    local payload = {
        exported_at = os.date("%Y-%m-%d %H:%M:%S"),
        bot_count = #snapshot,
        bots = snapshot,
    }

    local encoded, err = json.encode(payload, { indent = true })
    if not encoded then
        return false, err or "Failed to encode JSON"
    end
    return encoded
end

local function encodeSnapshotAsCSV(snapshot)
    headers = {
        "BotName",
        "Location",
        "SlotID",
        "SlotName",
        "ItemName",
        "ItemID",
        "AC",
        "HP",
        "Mana",
        "Damage",
        "Delay",
        "Icon",
        "Quantity",
        "Charges",
        "StackSize",
        "NoDrop",
        "ItemURL",
    }

    local function csvEscape(value)
        if value == nil then return "" end
        local str = tostring(value)
        if str:find('[",\n]') then
            str = '"' .. str:gsub('"', '""') .. '"'
        end
        return str
    end

    local lines = {}
    lines[#lines + 1] = table.concat(headers, ",")

    local function appendItems(location, items, botName)
        for _, item in ipairs(items or {}) do
            local url = item and item.itemlink or nil
            local hyperlink = nil
            if url and tostring(url):match('^https?://') then
                local text = item and item.name or url
                hyperlink = string.format('=HYPERLINK("%s","%s")', tostring(url), tostring(text))
            end

            local columns = {
                csvEscape(botName),
                csvEscape(location),
                csvEscape(item.slotid),
                csvEscape(item.slotname),
                csvEscape(item.name),
                csvEscape(item.itemID),
                csvEscape(item.ac),
                csvEscape(item.hp),
                csvEscape(item.mana),
                csvEscape(item.damage),
                csvEscape(item.delay),
                csvEscape(item.icon),
                csvEscape(item.qty),
                csvEscape(item.charges),
                csvEscape(item.stackSize),
                csvEscape(item.nodrop),
                csvEscape(hyperlink or url or ""),
            }
            lines[#lines + 1] = table.concat(columns, ",")
        end
    end

    for _, bot in ipairs(snapshot) do
        local botName = bot.name or "Unknown"
        appendItems("Equipped", bot.equipped, botName)
        appendItems("Bag", bot.bags, botName)
        appendItems("Bank", bot.bank, botName)
    end

    return table.concat(lines, "\n") .. "\n"
end

function BotInventory.exportBotInventories(format, path)
    local exportFormat = (format and format:lower()) or "json"
    if exportFormat ~= "json" and exportFormat ~= "csv" then
        local message = string.format("[BotInventory] Unsupported export format: %s", tostring(format))
        print(message)
        return false, message
    end

    local snapshot = buildExportSnapshot()
    local targetPath = resolveExportPath(exportFormat, path)

    local contents
    if exportFormat == "json" then
        local encoded, err = encodeSnapshotAsJSON(snapshot)
        if not encoded then
            local message = string.format("[BotInventory] Failed to encode JSON: %s", tostring(err))
            print(message)
            return false, message
        end
        contents = encoded
    else
        contents = encodeSnapshotAsCSV(snapshot)
    end

    local ok, err = writeFile(targetPath, contents)
    if not ok then
        local message = string.format("[BotInventory] Failed to write export file '%s': %s", targetPath, tostring(err))
        print(message)
        return false, message
    end

    local successMessage = string.format("[BotInventory] Exported bot inventories to %s", targetPath)
    print(successMessage)
    return true, targetPath
end

BotInventory.buildExportSnapshot = buildExportSnapshot

function BotInventory.parseItemLinkData(itemLinkString)
    if not itemLinkString or itemLinkString == "" then return nil end

    local links = mq.ExtractLinks(itemLinkString)
    for _, link in ipairs(links) do
        if link.type == mq.LinkTypes.Item then
            local parsed = mq.ParseItemLink(link.link)
            -- Best-effort extraction: treat missing fields as nil (unknown)
            local ac, hp, mana, damage, delay = nil, nil, nil, nil, nil
            if parsed then
                -- First, try fields directly present on parsed
                ac     = parsed.ac or parsed.AC or ac
                hp     = parsed.hp or parsed.HP or hp
                mana   = parsed.mana or parsed.Mana or parsed.MANA or mana
                damage = parsed.damage or parsed.Damage or damage
                delay  = parsed.delay or parsed.Delay or delay
            end
            local iconID = 0
            if parsed then
                iconID = tonumber(parsed.iconID or parsed.IconID or parsed.icon or parsed.Icon or 0) or 0
                if iconID == 0 and link.icon then
                    iconID = tonumber(link.icon) or 0
                end
            end

            return {
                itemID   = parsed and parsed.itemID or nil,
                iconID   = iconID,
                icon     = iconID,
                linkData = link,
                ac       = ac ~= nil and (tonumber(ac) or 0) or nil,
                hp       = hp ~= nil and (tonumber(hp) or 0) or nil,
                mana     = mana ~= nil and (tonumber(mana) or 0) or nil,
                damage   = damage ~= nil and (tonumber(damage) or 0) or nil,
                delay    = delay ~= nil and (tonumber(delay) or 0) or nil,
            }
        end
    end
    return nil
end

local function cacheItemStats(item)
    if not item then return end
    local itemID = tonumber(item.itemID or item.ItemID)
    if not itemID or itemID <= 0 then return end
    local cache = BotInventory._itemStatCache[itemID] or {}

    local icon = tonumber(item.icon or item.iconID or 0)
    if icon and icon > 0 then cache.icon = icon end

    local ac = tonumber(item.ac or 0)
    if ac and ac ~= 0 then cache.ac = ac end

    local hp = tonumber(item.hp or 0)
    if hp and hp ~= 0 then cache.hp = hp end

    local mana = tonumber(item.mana or 0)
    if mana and mana ~= 0 then cache.mana = mana end

    local dmg = tonumber(item.damage or 0)
    if dmg and dmg ~= 0 then cache.damage = dmg end

    local delay = tonumber(item.delay or 0)
    if delay and delay ~= 0 then cache.delay = delay end

    BotInventory._itemStatCache[itemID] = cache
end

local function hydrateItemFromCache(item)
    if not item then return end
    local itemID = tonumber(item.itemID or item.ItemID)
    if not itemID or itemID <= 0 then return end
    local cache = BotInventory._itemStatCache[itemID]
    if not cache then return end

    if tonumber(item.icon or 0) == 0 and cache.icon then
        item.icon = cache.icon
        item.iconID = cache.icon
    end
    if (not item.ac or tonumber(item.ac or 0) == 0) and cache.ac then
        item.ac = cache.ac
    end
    if (not item.hp or tonumber(item.hp or 0) == 0) and cache.hp then
        item.hp = cache.hp
    end
    if (not item.mana or tonumber(item.mana or 0) == 0) and cache.mana then
        item.mana = cache.mana
    end
    if (not item.damage or tonumber(item.damage or 0) == 0) and cache.damage then
        item.damage = cache.damage
    end
    if (not item.delay or tonumber(item.delay or 0) == 0) and cache.delay then
        item.delay = cache.delay
    end
end

function BotInventory.getBotListEvent(line, botIndex, botName, level, gender, race, class)
    if not BotInventory.refreshing_bot_list then return end
    local owner = BotInventory._owner or resolveCurrentOwner()
    BotInventory._owner = owner
    -- Normalize name from token or table
    if type(botName) == "table" and botName.text then botName = botName.text end
    if not botName or botName == "" then return end

    local s = tostring(line or "")
    local parsedLevel, tail = s:match("is a Level%s+(%d+)%s+(.+)%s+owned by You%.")
    if not parsedLevel then
        parsedLevel, tail = s:match("is a Level%s+(%d+)%s+(.+)%s+owned by You")
    end

    local parsedGender, parsedRace, parsedClass
    if tail then
        parsedGender, tail = tail:match("^(%S+)%s+(.+)$")
        if parsedGender and tail then
            parsedClass = tail:match("(%S+)$")
            if parsedClass then
                parsedRace = tail:sub(1, #tail - #parsedClass - 1)
                parsedRace = parsedRace and parsedRace:match("^%s*(.-)%s*$") or nil
            end
        end
    end
    -- Fallbacks to provided tokens if parsing failed
    parsedLevel = tonumber(parsedLevel) or tonumber(level) or nil
    parsedGender = parsedGender or gender
    parsedRace = parsedRace or race
    parsedClass = parsedClass or class

    if not BotInventory.bot_list_capture_set[botName] then
        BotInventory.bot_list_capture_set[botName] = {
            Name = botName,
            Index = tonumber(botIndex),
            Level = parsedLevel,
            Gender = parsedGender,
            Race = parsedRace,
            Class = parsedClass,
            Owner = owner,
        }
    else
        local e = BotInventory.bot_list_capture_set[botName]
        e.Level = e.Level or parsedLevel
        e.Gender = e.Gender or parsedGender
        e.Race = e.Race or parsedRace
        e.Class = e.Class or parsedClass
        e.Owner = owner or e.Owner
    end
end

local function displayBotInventory(line, slotNum, slotName)
    if not BotInventory.current_bot_request then return end

    local botName = BotInventory.current_bot_request

    -- Verify current target matches expected bot to prevent data crossover
    local currentTarget = mq.TLO.Target
    local targetName = currentTarget and currentTarget.Name and currentTarget.Name() or ""
    if targetName ~= botName then
        print(string.format(
            "[BotInventory] WARNING: Target mismatch! Expected '%s' but target is '%s'. Ignoring inventory data.",
            botName,
            targetName))
        return
    end

    local slotId = tonumber(slotNum)
    if not slotId then
        print(string.format("[BotInventory] WARNING: Received inventory line without numeric slot for %s: %s",
            botName, tostring(line)))
        return
    end

    local buffer = getCaptureBuffer(botName) or beginCaptureBuffer(botName)
    buffer.total_lines = buffer.total_lines + 1
    buffer.last_line_time = os.clock()
    if not buffer.slots_seen[slotId] then
        buffer.slots_seen[slotId] = true
        buffer.processed_slots = buffer.processed_slots + 1
    end

    local itemlink = (mq.ExtractLinks(line) or {})[1] or { text = "Empty", link = "N/A" }

    if itemlink.text ~= "Empty" and itemlink.link ~= "N/A" then
        local parsedItem = BotInventory.parseItemLinkData(line)

        local newItem = {
            name = itemlink.text,
            slotid = slotId,
            slotname = slotName,
            itemlink = line,
            rawline = line,
            itemID = parsedItem and parsedItem.itemID or nil,
            icon = (parsedItem and (parsedItem.iconID or parsedItem.icon or 0)) or 0,
            stackSize = parsedItem and parsedItem.stackSize or nil,
            charges = parsedItem and parsedItem.charges or nil,
            ac = parsedItem and parsedItem.ac or nil,
            hp = parsedItem and parsedItem.hp or nil,
            mana = parsedItem and parsedItem.mana or nil,
            damage = parsedItem and parsedItem.damage or nil,
            delay = parsedItem and parsedItem.delay or nil,
            qty = 1,
            nodrop = 1
        }
        hydrateItemFromCache(newItem)
        buffer.items_by_slot[slotId] = newItem
        cacheItemStats(newItem)
    else
        buffer.items_by_slot[slotId] = nil
    end

    BotInventory._capture_count[botName] = buffer.processed_slots
end


function BotInventory.getCurrentOwner()
    BotInventory._owner = BotInventory._owner or resolveCurrentOwner()
    return BotInventory._owner
end

function BotInventory.isBotOwnedByCurrentCharacter(botName)
    if not botName or botName == '' then return false end
    local owner = BotInventory.getCurrentOwner()
    local data = BotInventory.bot_inventories and BotInventory.bot_inventories[botName]
    if data and data.owner then
        return data.owner == owner
    end
    local meta = BotInventory.bot_list_capture_set and BotInventory.bot_list_capture_set[botName]
    if meta and meta.Owner then
        return meta.Owner == owner
    end
    return true
end

function BotInventory.getAllBots()
    local names = {}
    if BotInventory.bot_list_capture_set then
        for name in pairs(BotInventory.bot_list_capture_set) do
            if BotInventory.isBotOwnedByCurrentCharacter(name) then
                table.insert(names, name)
            end
        end
    end
    table.sort(names)
    return names
end

function BotInventory.refreshBotList()
    if BotInventory.refreshing_bot_list then
        return
    end

    print("[BotInventory] Refreshing bot list...")
    BotInventory.refreshing_bot_list = true
    BotInventory.bot_list_capture_set = {}
    BotInventory.bot_list_start_time = os.time()

    mq.cmd("/say ^botlist")
end

function BotInventory.processBotListResponse()
    if BotInventory.refreshing_bot_list and BotInventory.bot_list_start_time then
        local elapsed = os.time() - BotInventory.bot_list_start_time

        if elapsed >= 3 then
            BotInventory.refreshing_bot_list = false
            BotInventory.cached_bot_list = {}
            for botName, _ in pairs(BotInventory.bot_list_capture_set) do
                if BotInventory.isBotOwnedByCurrentCharacter(botName) then
                    table.insert(BotInventory.cached_bot_list, botName)
                end
            end

            --print(string.format("[BotInventory] Found %d bots: %s", #BotInventory.cached_bot_list, table.concat(BotInventory.cached_bot_list, ", ")))
            BotInventory.bot_list_start_time = nil
        end
    end
end

-- Global skip check function (will be set by UI)
BotInventory.skipCheckFunction = nil

function BotInventory.requestBotInventory(botName)
    -- Check if bot should be skipped before starting request
    if BotInventory.skipCheckFunction and BotInventory.skipCheckFunction(botName) then
        print(string.format("[BotInventory] Skipping bot %s due to failure history", botName))
        return false
    end

    if BotInventory.current_bot_request == botName and BotInventory.bot_request_phase ~= 0 then
        return false
    end

    -- Start request with a fresh capture buffer for this bot
    beginCaptureBuffer(botName)
    BotInventory._capture_count[botName] = 0
    BotInventory.current_bot_request = botName
    BotInventory.bot_request_start_time = os.time()
    BotInventory.spawn_issued_time = nil
    BotInventory.target_issued_time = os.clock()
    BotInventory.invlist_issued_time = nil
    BotInventory.bot_request_phase = 1

    targetBotByName(botName)
    --print(string.format("[BotInventory DEBUG] Issued initial target attempt for %s", botName))
    return true
end

function BotInventory.processBotInventoryResponse()
    local botName = BotInventory.current_bot_request
    if botName and BotInventory.bot_request_start_time then
        local elapsed = os.time() - BotInventory.bot_request_start_time
        if elapsed >= 10 then
            failActiveRequest(botName, string.format("Timeout waiting for inventory from %s", botName))
            return
        end
    end

    if not botName then
        return
    end

    if BotInventory.bot_request_phase == 4 then
        local buffer = getCaptureBuffer(botName)
        local expectedSlots = BotInventory.capture_expected_slots or 23
        local settleDelay = BotInventory.capture_settle_delay or 0.2
        local timeoutSeconds = BotInventory.capture_timeout_seconds or 4
        local slotTolerance = BotInventory.capture_slot_tolerance or 0
        local minAcceptableSlots = math.max(1, expectedSlots - slotTolerance)

        if buffer and buffer.processed_slots >= expectedSlots then
            local lastLineAge = buffer.last_line_time and (os.clock() - buffer.last_line_time) or 0
            if lastLineAge >= settleDelay then
                finalizeBotInventoryCapture(botName, buffer)
                return
            end
        end

        local pendingAge = BotInventory.invlist_issued_time and (os.clock() - BotInventory.invlist_issued_time) or 0
        if pendingAge and pendingAge >= timeoutSeconds then
            local captured = buffer and buffer.processed_slots or 0
            if slotTolerance > 0 and buffer and captured >= minAcceptableSlots then
                print(string.format(
                    "[BotInventory] Allowing incomplete inventory for %s (%d/%d slots, tolerance %d)",
                    botName, captured, expectedSlots, slotTolerance))
                finalizeBotInventoryCapture(botName, buffer)
                return
            end
            failActiveRequest(botName, string.format(
                "Incomplete inventory from %s (%d/%d slots)", botName, captured, expectedSlots))
            return
        end
    end

    if BotInventory.bot_request_phase == 1 and BotInventory.target_issued_time then
        if os.clock() - BotInventory.target_issued_time >= 0.5 then
            local currentTarget = mq.TLO.Target
            local targetName = currentTarget and currentTarget.Name and currentTarget.Name()
            if targetName == botName then
                mq.cmd("/say ^invlist")
                BotInventory.invlist_issued_time = os.clock()
                BotInventory.target_issued_time = nil
                BotInventory.bot_request_phase = 4
            else
                mq.cmdf("/say ^spawn %s", botName)
                BotInventory.spawn_issued_time = os.clock()
                BotInventory.bot_request_phase = 2
            end
        end
    elseif BotInventory.bot_request_phase == 2 and BotInventory.spawn_issued_time then
        if os.clock() - BotInventory.spawn_issued_time >= 2.0 then
            targetBotByName(botName)
            BotInventory.target_issued_time = os.clock()
            BotInventory.spawn_issued_time = nil
            BotInventory.bot_request_phase = 3
        end
    elseif BotInventory.bot_request_phase == 3 and BotInventory.target_issued_time then
        local currentTarget = mq.TLO.Target
        local targetName = currentTarget and currentTarget.Name and currentTarget.Name()
        if targetName == botName then
            if os.clock() - BotInventory.target_issued_time >= 1.0 then
                mq.cmd("/say ^invlist")
                BotInventory.invlist_issued_time = os.clock()
                BotInventory.target_issued_time = nil
                BotInventory.bot_request_phase = 4
            end
        elseif os.clock() - BotInventory.target_issued_time >= 3.0 then
            failActiveRequest(botName, string.format("Failed to target %s after 3 seconds", botName))
        end
    end
end


local function displayBotUnequipResponse(line, slotNum, itemName)
    if not BotInventory.current_bot_request then return end

    local botName = BotInventory.current_bot_request
    print(string.format("[BotInventory] %s unequipped %s from slot %s", botName, itemName or "item", slotNum or "unknown"))

    -- Remove the item from our cached inventory if we have it
    if BotInventory.bot_inventories[botName] and BotInventory.bot_inventories[botName].equipped then
        local removed = false
        for i = #BotInventory.bot_inventories[botName].equipped, 1, -1 do
            local item = BotInventory.bot_inventories[botName].equipped[i]
            if tonumber(item.slotid) == tonumber(slotNum) then
                table.remove(BotInventory.bot_inventories[botName].equipped, i)
                print(string.format("[BotInventory] Removed %s from cached inventory", item.name or "item"))
                removed = true
                break
            end
        end
        if removed then
            local meta = BotInventory.bot_list_capture_set and BotInventory.bot_list_capture_set[botName] or nil
            local ok, err = db.save_bot_inventory(botName, BotInventory.bot_inventories[botName], meta)
            if not ok then
                print(string.format("[BotInventory][DB] Failed to persist after unequip for %s: %s", botName,
                    tostring(err)))
            end
        end
    end
end

function BotInventory.requestBotUnequip(botName, slotID)
    if not botName or not slotID then
        print("[BotInventory] Error: botName and slotID required for unequip")
        return false
    end

    local botSpawn = mq.TLO.Spawn(string.format("= %s", botName))
    if botSpawn() then
        print(string.format("[BotInventory] Targeting and issuing unequip to %s at ID %d", botName, botSpawn.ID()))
        mq.cmdf("/target id %d", botSpawn.ID())
        mq.delay(500)
        mq.cmdf("/say ^invremove %s", slotID)
        return true
    else
        print(string.format("[BotInventory] Could not find bot spawn for unequip command: %s", botName))
        return false
    end
end

function BotInventory.getBotEquippedItem(botName, slotID)
    if not BotInventory.bot_inventories[botName] or not BotInventory.bot_inventories[botName].equipped then
        return nil
    end

    for _, item in ipairs(BotInventory.bot_inventories[botName].equipped) do
        if tonumber(item.slotid) == tonumber(slotID) then
            return item
        end
    end
    return nil
end

function BotInventory.process()
    BotInventory.processBotListResponse()
    BotInventory.processBotInventoryResponse()
end

function BotInventory.executeItemLink(item)
    if not item then
        print("[BotInventory DEBUG] No item provided.")
        return false
    end
    print(string.format("[BotInventory DEBUG] Raw line: %s", item.rawline or "nil"))
    local links = mq.ExtractLinks(item.rawline or "")
    if not links or #links == 0 then
        print("[BotInventory DEBUG] No links extracted.")
        return false
    end
    print(string.format("[BotInventory DEBUG] Extracted %d link(s):", #links))
    for i, link in ipairs(links) do
        local txt = link.text or "<nil>"
        local lnk = link.link or "<nil>"
        print(string.format("  [%d] Text: '%s' | Link: '%s'", i, txt, lnk))
        if link.type == mq.LinkTypes.Item then
            local parsedItem = mq.ParseItemLink(link.link)
            if parsedItem then
                print(string.format("    Item ID: %s, Icon ID: %s",
                    parsedItem.itemID or "N/A",
                    parsedItem.iconID or "N/A"))
            end
        end
    end
    return true
end

function BotInventory.onItemClick(item)
    if item then
        return BotInventory.executeItemLink(item)
    end
    return false
end

function BotInventory.getBotInventory(botName)
    return BotInventory.bot_inventories[botName]
end

-- Apply a known equipped item change using the cursor item data (no ^invlist roundtrip)
-- Replaces the equipped item in the given slot and persists to SQLite immediately.
-- Parameters:
--  botName   - target bot name
--  slotID    - numeric slot id
--  slotName  - human readable slot name
--  itemID    - numeric itemID of the cursor item
--  itemName  - name of the cursor item
--  ac,hp,mana,icon (numbers) - optional stats/icon to set; nil treated as 0
--  damage,delay (numbers) - optional weapon stats; nil treated as 0
function BotInventory.applySwapFromCursor(botName, slotID, slotName, itemID, itemName, ac, hp, mana, icon, damage, delay)
    assert(slotID or slotName, "Must include either a Item Slot ID or Item Slot Name")
    assert(itemName, "Items have to have a name!")
    if not botName or slotID == nil then return false, 'bad args' end

    -- Ensure bot cache exists
    local record = ensureBotInventoryRecord(botName)
    local eq = record and record.equipped or {}

    local newItem = {
        name = itemName,
        slotid = tonumber(slotID),
        slotname = slotName,
        itemlink = nil,
        rawline = nil,
        itemID = tonumber(itemID) or 0,
        icon = tonumber(icon or 0) or 0,
        ac = tonumber(ac or 0) or 0,
        hp = tonumber(hp or 0) or 0,
        mana = tonumber(mana or 0) or 0,
        damage = tonumber(damage or 0) or 0,
        delay = tonumber(delay or 0) or 0,
        qty = 1,
        nodrop = 1,
    }

    hydrateItemFromCache(newItem)

    -- Replace existing slot entry or insert
    local replaced = false
    for i = 1, #eq do
        local it = eq[i]
        if tonumber(it.slotid) == tonumber(slotID) then
            eq[i] = newItem
            replaced = true
            break
        end
    end
    if not replaced then table.insert(eq, newItem) end
    cacheItemStats(newItem)

    -- Persist to DB with available bot meta
    local meta = BotInventory.bot_list_capture_set and BotInventory.bot_list_capture_set[botName] or nil
    local ok, err = db.save_bot_inventory(botName, BotInventory.bot_inventories[botName], meta)
    if not ok then
        print(string.format('[BotInventory][DB] Failed to persist swap for %s: %s', botName, tostring(err)))
        return false, err
    end

    return true
end

-- Compare items and detect mismatches that need re-scanning
function BotInventory.compareInventoryData(botName, oldData, newData)
    if not oldData or not newData then return {} end
    if not oldData.equipped or not newData.equipped then return {} end

    local mismatches = {}
    local oldBySlot = {}
    local newBySlot = {}

    -- Index old items by slot ID
    for _, item in ipairs(oldData.equipped) do

        if item.slotid then
            hydrateItemFromCache(item)
            oldBySlot[tonumber(item.slotid)] = item
        end
    end

    -- Index new items by slot ID
    for _, item in ipairs(newData.equipped) do
        if item.slotid then
            hydrateItemFromCache(item)
            newBySlot[tonumber(item.slotid)] = item
        end
    end

    -- Compare items in each slot
    for slotId, newItem in pairs(newBySlot) do
        local oldItem = oldBySlot[slotId]
        local needsScan = false
        local reason = ""

        if not oldItem then
            -- New item in this slot
            needsScan = (not newItem.ac or tonumber(newItem.ac or 0) == 0) and
                (not newItem.hp or tonumber(newItem.hp or 0) == 0) and
                (not newItem.mana or tonumber(newItem.mana or 0) == 0) and
                (not newItem.damage or tonumber(newItem.damage or 0) == 0) and
                (not newItem.delay or tonumber(newItem.delay or 0) == 0)
            reason = "new item with missing stats"
        elseif oldItem.name ~= newItem.name or oldItem.itemID ~= newItem.itemID then
            -- Different item in the same slot
            needsScan = (not newItem.ac or tonumber(newItem.ac or 0) == 0) and
                (not newItem.hp or tonumber(newItem.hp or 0) == 0) and
                (not newItem.mana or tonumber(newItem.mana or 0) == 0) and
                (not newItem.damage or tonumber(newItem.damage or 0) == 0) and
                (not newItem.delay or tonumber(newItem.delay or 0) == 0)
            reason = string.format("item changed from '%s' to '%s'", oldItem.name or "unknown", newItem.name or "unknown")
        else
            -- Same item, check for stat mismatches
            local oldAC = tonumber(oldItem.ac or 0) or 0
            local oldHP = tonumber(oldItem.hp or 0) or 0
            local oldMana = tonumber(oldItem.mana or 0) or 0
            local newAC = tonumber(newItem.ac or 0) or 0
            local newHP = tonumber(newItem.hp or 0) or 0
            local newMana = tonumber(newItem.mana or 0) or 0

            -- If old item had stats but new item doesn't, or stats changed significantly
            local oldDamage = tonumber(oldItem.damage or 0) or 0
            local oldDelay = tonumber(oldItem.delay or 0) or 0
            local newDamage = tonumber(newItem.damage or 0) or 0
            local newDelay = tonumber(newItem.delay or 0) or 0

            if (oldAC > 0 or oldHP > 0 or oldMana > 0 or oldDamage > 0 or oldDelay > 0) and
                (newAC == 0 and newHP == 0 and newMana == 0 and newDamage == 0 and newDelay == 0) then
                needsScan = true
                reason = "stats missing from fresh data"
            elseif (newAC == 0 and newHP == 0 and newMana == 0 and newDamage == 0 and newDelay == 0) and
                (not newItem.itemlink or newItem.itemlink == "") then
                needsScan = true
                reason = "missing stats and itemlink"
            end
        end

        if needsScan then
            table.insert(mismatches, {
                item = newItem,
                slotId = slotId,
                reason = reason,
                botName = botName
            })
        end
    end

    return mismatches
end

function BotInventory.init()
    local owner = resolveCurrentOwner()

    if not BotInventory._events_registered then
        mq.event("GetBotList", "Bot #1# #*# #2# is a Level #3# #4# #5# #6# owned by You.#*", BotInventory.getBotListEvent)
        mq.event("BotInventory", "Slot #1# (#2#) #*#", displayBotInventory, { keepLinks = true })
        mq.event("BotUnequip", "#1# unequips #2# from slot #3#", displayBotUnequipResponse)
        BotInventory._events_registered = true
    end

    if BotInventory.initialized and BotInventory._owner == owner then
        return true
    end

    resetStateForOwner(owner)

    -- Initialize database and pre-load prior state
    local ok, err = db.init()
    if not ok then
        print(string.format("[BotInventory][DB] Initialization failed: %s", tostring(err)))
    else
        local loaded = db.load_all() or {}
        for name, data in pairs(loaded) do
            data.owner = owner
            BotInventory.bot_inventories[name] = data
            -- Seed capture set so UI can list bots immediately
            BotInventory.bot_list_capture_set[name] = {
                Name = name,
                Owner = owner,
                Class = data.class or data.Class,
                Level = data.level or data.Level,
                Gender = data.gender or data.Gender,
                Race = data.race or data.Race,
            }
            for _, item in ipairs(data.equipped or {}) do
                cacheItemStats(item)
            end
        end
        print(string.format("[BotInventory][DB] Loaded %d bot(s) from persistence",
            (function(t)
                local c = 0
                for _ in pairs(t) do c = c + 1 end
                return c
            end)(loaded)))
    end

    print("[BotInventory] Bot inventory system initialized")

    BotInventory.cached_bot_list = {}
    BotInventory.initialized = true
    return true
end

return BotInventory
