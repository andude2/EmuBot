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
BotInventory._web_botlist_coroutine = nil
BotInventory._last_web_botlist_error = nil
BotInventory._web_bot_inventory_coroutines = {}
BotInventory._last_web_inventory_error = {}
BotInventory._debug = false
BotInventory._debug_verbose = false

local http
do
    local ok, mod = pcall(require, 'socket.http')
    if ok and mod then
        http = mod
        http.TIMEOUT = http.TIMEOUT or 5
    end
end

local url_escape
do
    local ok, mod = pcall(require, 'socket.url')
    if ok and mod and mod.escape then
        url_escape = mod.escape
    end
end

local function friendly_web_error(reason)
    if not reason then return 'unknown error' end
    if reason == 'http_unavailable' then
        return 'socket.http module unavailable'
    elseif reason == 'missing_clean_name' then
        return 'unable to determine CleanName'
    elseif reason == 'invalid_clean_name' then
        return 'CleanName contains unsupported characters'
    elseif reason == 'no_bots_found' then
        return 'web response contained no bots'
    elseif reason == 'unsupported_server' then
        return 'server does not support web bot list'
    elseif reason == 'coroutine_error' then
        return 'coroutine execution failed'
    elseif reason == 'coroutine_creation_failed' then
        return 'unable to create coroutine'
    elseif reason == 'ssl_not_available' then
        return 'https unsupported (missing LuaSec)'
    elseif reason == 'handshake_failed' then
        return 'TLS handshake failed'
    elseif reason == 'connect_failed' then
        return 'connection failed'
    elseif reason == 'send_failed' then
        return 'send failed'
    elseif reason == 'receive_failed' then
        return 'receive failed'
    elseif reason == 'request_failed' then
        return 'http request failed'
    elseif reason == 'no_items_found' then
        return 'web response contained no equipped items'
    end
    return tostring(reason)
end

-- Simple blocking HTTP request function
local function fetch_http_body(url)
    if not http then
        return false, 'http_unavailable'
    end
    if not url then
        return false, 'invalid_url'
    end

    local body, code, headers, status = http.request(url)
    if not body then
        return false, status or code or 'request_failed'
    end
    if tonumber(code) ~= 200 then
        return false, status or string.format('http_%s', tostring(code))
    end

    return true, body, code, status
end

local function apply_web_botlist(result, clean_name)
    BotInventory.bot_list_capture_set = {}
    BotInventory.cached_bot_list = {}
    for _, entry in ipairs(result) do
        BotInventory.bot_list_capture_set[entry.Name] = entry
        table.insert(BotInventory.cached_bot_list, entry.Name)
    end
    table.sort(BotInventory.cached_bot_list, function(a, b) return a:lower() < b:lower() end)
    BotInventory._last_web_botlist_error = nil
    BotInventory.refreshing_bot_list = false
    BotInventory.bot_list_start_time = nil
    BotInventory._web_botlist_coroutine = nil
    print(string.format('[BotInventory] Loaded %d bots from karanaeq.com for %s', #result, clean_name or 'unknown'))
end

local function handle_web_botlist_failure(reason)
    local friendly = friendly_web_error(reason)
    if reason and reason ~= 'unsupported_server' then
        print(string.format('[BotInventory] Web bot list fetch failed (%s); in-game fallback temporarily disabled for HTTP testing.', friendly))
    end
    BotInventory._last_web_botlist_error = friendly
    BotInventory._web_botlist_coroutine = nil
    BotInventory.refreshing_bot_list = false
    BotInventory.bot_list_start_time = nil
    BotInventory.bot_list_capture_set = {}
    BotInventory.cached_bot_list = {}

    -- fallback to in-game /say command
    BotInventory.refreshing_bot_list = true
    BotInventory.bot_list_capture_set = {}
    BotInventory.bot_list_start_time = os.time()
    mq.cmd("/say ^botlist")
end

local function get_server_name()
    if mq and mq.TLO and mq.TLO.EverQuest and mq.TLO.EverQuest.Server then
        local ok, server = pcall(function() return mq.TLO.EverQuest.Server() end)
        if ok and server and server ~= '' then
            return tostring(server)
        end
    end
    return nil
end

local function get_clean_name()
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
    return nil
end

local function sanitize_char_name(name)
    if not name then return nil end
    local trimmed = name:match('^%s*(.-)%s*$') or ''
    if trimmed == '' then return nil end
    local letters_only = trimmed:gsub("[^A-Za-z]", "")
    if letters_only == '' then return nil end
    return letters_only:lower()
end

local function should_use_web_botlist()
    local server = get_server_name()
    if not server then return false end
    return server:lower() == 'karana'
end

local function parse_bots_from_html(html)
    local bots = {}
    if not html or html == '' then return bots end

    local index = 0
    for block in html:gmatch("<a%s+class=['\"]CB_Bot_Avatar_Window['\"][^>]*>([%s%S]-)</a>") do
        local name, detail = block:match("<div%s+class=['\"]CB_Bot_Caption['\"]>%s*<p>([^<]+)</p>%s*<p>([^<]+)</p>")
        if name and detail then
            local normalized_name = name:lower()
            if not normalized_name:find("%-deleted%-%d+") then
                index = index + 1
                local level_str, tail = detail:match("^(%d+)%s+(.+)$")
                local class_name, race_name
                if tail then
                    class_name = tail:match("(%S+)$")
                    if class_name then
                        local cutoff = #tail - #class_name - 1
                        if cutoff > 0 then
                            race_name = tail:sub(1, cutoff)
                            if race_name then
                                race_name = race_name:gsub('^%s+', ''):gsub('%s+$', '')
                            end
                        end
                    else
                        race_name = tail
                    end
                end

                if not race_name and tail then
                    race_name = tail
                end

                if race_name then
                    race_name = race_name:gsub('^%s+', ''):gsub('%s+$', '')
                end
                if class_name then
                    class_name = class_name:gsub('^%s+', ''):gsub('%s+$', '')
                end

                local gender
                local gender_id = block:match("gender_(%d+)_face_")
                if gender_id == '0' then
                    gender = 'Male'
                elseif gender_id == '1' then
                    gender = 'Female'
                end

                bots[#bots + 1] = {
                    Name = name,
                    Index = index,
                    Level = level_str and tonumber(level_str) or nil,
                    Race = race_name,
                    Class = class_name,
                    Gender = gender,
                }
            end
        end
    end

    return bots
end

local function try_fetch_botlist_from_web()
    if not http and not copas_http then
        return false, 'http_unavailable'
    end
    if not should_use_web_botlist() then
        return false, 'unsupported_server'
    end

    local clean_name = get_clean_name()
    if not clean_name then
        return false, 'missing_clean_name'
    end

    local sanitized = sanitize_char_name(clean_name)
    if not sanitized then
        return false, 'invalid_clean_name'
    end

    local url = string.format('https://karanaeq.com/Char/index.php?page=bots&char=%s', sanitized)
    local ok, body, code, status = fetch_http_body(url)
    if not ok then
        return false, body -- error message is in body when ok is false
    end
    if tonumber(code) ~= 200 then
        return false, status or string.format('http_%s', tostring(code))
    end

    local bots = parse_bots_from_html(body)
    if #bots == 0 then
        return false, 'no_bots_found'
    end

    return true, bots, clean_name
end

local function decode_html_entities(str)
    if not str then return '' end
    local subst = {
        ['&nbsp;'] = ' ',
        ['&amp;'] = '&',
        ['&quot;'] = '"',
        ['&#39;'] = "'",
        ['&lt;'] = '<',
        ['&gt;'] = '>'
    }
    str = str:gsub('&nbsp;', ' ')
    for entity, replacement in pairs(subst) do
        str = str:gsub(entity, replacement)
    end
    return str
end

local function parse_number_field(value)
    if not value then return nil end
    local sanitized = tostring(value):gsub('[,%+]', '')
    sanitized = sanitized:gsub('%s+', '')
    if sanitized == '' then return nil end
    local num = tonumber(sanitized)
    return num
end

local function sanitize_for_url(name)
    if not name then return nil end
    local trimmed = name:match('^%s*(.-)%s*$') or ''
    if trimmed == '' then return nil end
    if url_escape then
        return url_escape(trimmed)
    end
    return trimmed
end

local function parse_bot_inventory_html(botName, html)
    if not html or html == '' then return {} end
    local collapsed = html:gsub('%s+', ' ')
    local items = {}

    local pattern = "<div%s+class=['\"]WindowComplex[^>]-id=['\"]slot(%d+)[\"'][^>]*>"
    local pos = 1

    while true do
        local startIdx, endIdx, slotId = collapsed:find(pattern, pos)
        if not startIdx then break end

        local nextStart = collapsed:find("<div%s+class=['\"]WindowComplex", endIdx + 1)
        local blockEnd = nextStart and (nextStart - 1) or #collapsed
        local fullBlock = collapsed:sub(startIdx, blockEnd)
        pos = nextStart or (#collapsed + 1)

        local header = fullBlock:match("<div%s+class=['\"]WindowTitleBar['\"]>(.-)</div>")
        local link = header and header:match("<a%s+href=['\"]([^'\"]+)['\"]")
        local name = header and header:match("<a [^>]*>([^<]+)</a>")
        local itemID = link and link:match('id=(%d+)')
        local iconID = fullBlock:match("Slot%s+Item_(%d+)")
        local stats_html = fullBlock:match("<div%s+class=['\"]Stats['\"][^>]*>(.-)</div>%s*</div>")

        if stats_html then
            local stats_text = stats_html:gsub('<br ?/?>', '\n')
            stats_text = stats_text:gsub('<[^>]+>', '')
            stats_text = decode_html_entities(stats_text)
            stats_text = stats_text:gsub('\r', ''):gsub('\f', ''):gsub('\t', ' ')
            stats_text = stats_text:gsub('%s+\n', '\n'):gsub('\n%s+', '\n')
            stats_text = stats_text:gsub(' +', ' ')
            stats_text = stats_text:gsub('^%s+', ''):gsub('%s+$', '')

            local slotname = stats_text:match('Slot:%s*([^\n]+)')
            if slotname then
                slotname = slotname:gsub('%s+$', '')
            end

            local ac = parse_number_field(stats_text:match('AC:%s*([%d,%+]+)'))
            local hp = parse_number_field(stats_text:match('HP:%s*[%+]?([%d,]+)'))
            local mana = parse_number_field(stats_text:match('MANA:%s*[%+]?([%d,]+)'))
            local damage = parse_number_field(stats_text:match('DMG:%s*([%d,]+)'))
            local delay = parse_number_field(stats_text:match('Atk Delay:%s*([%d,]+)') or stats_text:match('Delay:%s*([%d,]+)'))
            local chargesText = stats_text:match('Charges:%s*([%w]+)')
            local charges
            if chargesText then
                local numericCharges = parse_number_field(chargesText)
                if numericCharges then
                    charges = numericCharges
                elseif chargesText:lower():find('infinite') then
                    charges = -1
                end
            end

            local item = {
                name = name or string.format('Slot %s', slotId),
                slotid = tonumber(slotId),
                slotname = slotname or string.format('Slot %s', slotId),
                itemlink = link,
                rawline = stats_text,
                itemID = itemID and tonumber(itemID) or nil,
                icon = iconID and tonumber(iconID) or 0,
                iconID = iconID and tonumber(iconID) or 0,
                ac = ac,
                hp = hp,
                mana = mana,
                damage = damage,
                delay = delay,
                qty = 1,
                nodrop = 1,
                charges = charges,
            }

            if BotInventory._debug and BotInventory._debug_verbose then
                print(string.format('[BotInventory DEBUG] Parsed item slot %s: ac=%s hp=%s mana=%s dmg=%s delay=%s',
                    tostring(slotId), tostring(ac), tostring(hp), tostring(mana), tostring(damage), tostring(delay)))
            end

            table.insert(items, item)
        end
    end

    table.sort(items, function(a, b)
        return (a.slotid or 0) < (b.slotid or 0)
    end)

    if BotInventory._debug and BotInventory._debug_verbose then
        print(string.format('[BotInventory DEBUG] Parsed %d equipped item(s) for %s', #items, tostring(botName)))
    elseif BotInventory._debug and #items == 0 then
        print(string.format('[BotInventory DEBUG] parse_bot_inventory_html: items=0 for %s', tostring(botName)))
    end

    return items
end

local function build_inventory_from_response(botName, body, code, status)
    if not body then
        return false, status or code or 'request_failed'
    end
    if tonumber(code) ~= 200 then
        return false, status or string.format('http_%s', tostring(code))
    end

    local items = parse_bot_inventory_html(botName, body)
    if #items == 0 then
        return false, 'no_items_found'
    end

    local inventory = {
        name = botName,
        equipped = items,
        bags = {},
        bank = {},
    }

    return true, inventory
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

local function apply_web_inventory(botName, inventory)
    local previous = BotInventory.bot_inventories[botName]
    BotInventory.bot_inventories[botName] = inventory
    BotInventory._capture_count[botName] = #(inventory.equipped or {})
    BotInventory._last_web_inventory_error[botName] = nil

    if previous and BotInventory.compareInventoryData then
        local mismatches = BotInventory.compareInventoryData(botName, previous, inventory)
        if mismatches and #mismatches > 0 then
            print(string.format('[BotInventory] Detected %d mismatched item(s) for %s, queueing for scan', #mismatches, botName))
            if BotInventory.onMismatchDetected then
                for _, mismatch in ipairs(mismatches) do
                    print(string.format('[BotInventory] Queueing %s (slot %s) for scan: %s', mismatch.item.name or 'unknown', tostring(mismatch.slotId), mismatch.reason))
                    BotInventory.onMismatchDetected(mismatch.item, botName, mismatch.reason)
                end
            end
        end
    end

    local meta = BotInventory.bot_list_capture_set and BotInventory.bot_list_capture_set[botName] or nil
    if db and db.save_bot_inventory then
        local ok, err = db.save_bot_inventory(botName, inventory, meta)
        if not ok then
            print(string.format('[BotInventory][DB] Failed to save inventory for %s: %s', botName, tostring(err)))
        end
    end
end

local function start_inventory_fallback(botName)
    BotInventory._capture_count[botName] = 0
    BotInventory.current_bot_request = botName
    BotInventory.bot_request_start_time = os.time()
    BotInventory.spawn_issued_time = nil
    BotInventory.target_issued_time = os.clock()
    BotInventory.invlist_issued_time = nil
    BotInventory.bot_request_phase = 1
    targetBotByName(botName)
end

local function handle_web_inventory_failure(botName, reason)
    local friendly = friendly_web_error(reason)
    BotInventory._last_web_inventory_error[botName] = friendly
    print(string.format('[BotInventory] Web inventory fetch failed for %s (%s)', tostring(botName), friendly))
    BotInventory._capture_count[botName] = 0
    if BotInventory.current_bot_request == botName then
        BotInventory.current_bot_request = nil
        BotInventory.bot_request_start_time = nil
    end
    if BotInventory.onBotFailure then
        BotInventory.onBotFailure(botName, friendly)
    end

    -- fallback to in-game inventory request (disabled during HTTP testing)
    print(string.format('[BotInventory DEBUG] Fallback to in-game disabled for testing: %s', botName))
    -- start_inventory_fallback(botName)
end

local function try_fetch_bot_inventory_from_web(botName)
    if not should_use_web_botlist() then
        return false, 'unsupported_server'
    end

    local encoded = sanitize_for_url(botName)
    if not encoded then
        return false, 'invalid_bot_name'
    end

    local url = string.format('https://karanaeq.com/Char/index.php?page=bot&bot=%s', encoded)
    local ok, body, code, status = fetch_http_body(url)
    if not ok then
        return false, body
    end

    return build_inventory_from_response(botName, body, code, status)
end

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
        copy.itemlink = item.itemlink  -- Fallback to original link if no itemID
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
                ac   = parsed.ac or parsed.AC or ac
                hp   = parsed.hp or parsed.HP or hp
                mana = parsed.mana or parsed.Mana or parsed.MANA or mana
                damage = parsed.damage or parsed.Damage or damage
                delay = parsed.delay or parsed.Delay or delay
            end
            local iconID = 0
            if parsed then
                iconID = tonumber(parsed.iconID or parsed.IconID or parsed.icon or parsed.Icon or 0) or 0
                if iconID == 0 and link.icon then
                    iconID = tonumber(link.icon) or 0
                end
            end

            return {
                itemID  = parsed and parsed.itemID or nil,
                iconID  = iconID,
                icon    = iconID,
                linkData = link,
                ac = ac ~= nil and (tonumber(ac) or 0) or nil,
                hp = hp ~= nil and (tonumber(hp) or 0) or nil,
                mana = mana ~= nil and (tonumber(mana) or 0) or nil,
                damage = damage ~= nil and (tonumber(damage) or 0) or nil,
                delay = delay ~= nil and (tonumber(delay) or 0) or nil,
            }
        end
    end
    return nil
end

function BotInventory.getBotListEvent(line, botIndex, botName, level, gender, race, class)
    if not BotInventory.refreshing_bot_list then return end
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
        }
    else
        local e = BotInventory.bot_list_capture_set[botName]
        e.Level = e.Level or parsedLevel
        e.Gender = e.Gender or parsedGender
        e.Race = e.Race or parsedRace
        e.Class = e.Class or parsedClass
    end
end

local function displayBotInventory(line, slotNum, slotName)
    if not BotInventory.current_bot_request then return end
    
    local botName = BotInventory.current_bot_request
    
    -- Verify current target matches expected bot to prevent data crossover
    local currentTarget = mq.TLO.Target
    local targetName = currentTarget and currentTarget.Name and currentTarget.Name() or ""
    if targetName ~= botName then
        print(string.format("[BotInventory] WARNING: Target mismatch! Expected '%s' but target is '%s'. Ignoring inventory data.", botName, targetName))
        return
    end
    
    local itemlink = (mq.ExtractLinks(line) or {})[1] or { text = "Empty", link = "N/A" }

    if not BotInventory.bot_inventories[botName] then
        BotInventory.bot_inventories[botName] = {
            name = botName,
            equipped = {},
            bags = {},
            bank = {}
        }
    end
    
    if itemlink.text ~= "Empty" and itemlink.link ~= "N/A" then
        local parsedItem = BotInventory.parseItemLinkData(line)
        
        local newItem = {
            name = itemlink.text,
            slotid = tonumber(slotNum),
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
        -- Merge behavior: replace per-slot, but preserve existing non-zero stats if new are zero
        local eq = BotInventory.bot_inventories[botName].equipped
        local replaced = false
        for i = 1, #eq do
            local it = eq[i]
            if tonumber(it.slotid) == tonumber(slotNum) then
                -- Preserve stats if new values are zero
                if (newItem.ac == nil) or ((newItem.ac or 0) == 0 and (it.ac or 0) ~= 0) then newItem.ac = newItem.ac ~= nil and newItem.ac or it.ac end
                if (newItem.hp == nil) or ((newItem.hp or 0) == 0 and (it.hp or 0) ~= 0) then newItem.hp = newItem.hp ~= nil and newItem.hp or it.hp end
                if (newItem.mana == nil) or ((newItem.mana or 0) == 0 and (it.mana or 0) ~= 0) then newItem.mana = newItem.mana ~= nil and newItem.mana or it.mana end
                if (newItem.icon or 0) == 0 and (it.icon or 0) ~= 0 then newItem.icon = it.icon end
                if (newItem.damage == nil) or ((newItem.damage or 0) == 0 and (it.damage or 0) ~= 0) then newItem.damage = newItem.damage ~= nil and newItem.damage or it.damage end
                if (newItem.delay == nil) or ((newItem.delay or 0) == 0 and (it.delay or 0) ~= 0) then newItem.delay = newItem.delay ~= nil and newItem.delay or it.delay end
                eq[i] = newItem
                replaced = true
                break
            end
        end
        if not replaced then table.insert(eq, newItem) end
        -- Count capture lines for this request
        BotInventory._capture_count[botName] = (BotInventory._capture_count[botName] or 0) + 1

        -- Debug output to track inventory storage (disabled to reduce spam)
        -- print(string.format("[BotInventory DEBUG] Stored item: %s (ID: %s, Icon: %s) in slot %s for bot %s", 
        --     item.name, 
        --     item.itemID or "N/A", 
        --     item.icon or "N/A", 
        --     slotName, 
        --     botName))
    end
end

function BotInventory.getAllBots()
    local names = {}
    if BotInventory.bot_list_capture_set then
        for name, botData in pairs(BotInventory.bot_list_capture_set) do
            table.insert(names, name)
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
    if should_use_web_botlist() and http then
        BotInventory.bot_list_start_time = os.time()
        BotInventory._web_botlist_coroutine = coroutine.create(function()
            coroutine.yield()
            local success, result, clean_name = try_fetch_botlist_from_web()
            coroutine.yield()
            if success then
                apply_web_botlist(result, clean_name)
            else
                handle_web_botlist_failure(result)
            end
        end)
        if BotInventory._web_botlist_coroutine then
            local ok, err = coroutine.resume(BotInventory._web_botlist_coroutine)
            if not ok then
                print(string.format('[BotInventory] Web bot list coroutine error: %s', tostring(err)))
                handle_web_botlist_failure('coroutine_error')
            end
        end
    else
        BotInventory.bot_list_capture_set = {}
        BotInventory.bot_list_start_time = os.time()
        mq.cmd("/say ^botlist")
    end
end

function BotInventory.processBotListResponse()
    if BotInventory.refreshing_bot_list and BotInventory.bot_list_start_time then
        local elapsed = os.time() - BotInventory.bot_list_start_time
        
        if elapsed >= 3 then
            BotInventory.refreshing_bot_list = false
            BotInventory.cached_bot_list = {}
            for botName, botData in pairs(BotInventory.bot_list_capture_set) do
                table.insert(BotInventory.cached_bot_list, botName)
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

    if should_use_web_botlist() and http then
        if BotInventory._web_bot_inventory_coroutines[botName] then
            return true
        end

        BotInventory.current_bot_request = botName
        BotInventory.bot_request_phase = 0
        BotInventory.bot_request_start_time = os.time()
        BotInventory._capture_count[botName] = 0

        local co = coroutine.create(function()
            coroutine.yield()
            local success, payload = try_fetch_bot_inventory_from_web(botName)
            coroutine.yield()
            if success then
                apply_web_inventory(botName, payload)
            else
                if BotInventory._debug then
                    print(string.format('[BotInventory DEBUG] Web inventory raw response for %s: %s', botName, tostring(payload or 'nil')))
                end
                handle_web_inventory_failure(botName, payload)
            end
            BotInventory._web_bot_inventory_coroutines[botName] = nil
            BotInventory.current_bot_request = nil
            BotInventory.bot_request_phase = 0
            BotInventory.bot_request_start_time = nil
        end)

        if not co then
            handle_web_inventory_failure(botName, 'coroutine_creation_failed')
            return false
        end

        BotInventory._web_bot_inventory_coroutines[botName] = co
        local ok, err = coroutine.resume(co)
        if not ok then
            print(string.format('[BotInventory] Web inventory coroutine error for %s: %s', tostring(botName), tostring(err)))
            BotInventory._web_bot_inventory_coroutines[botName] = nil
            BotInventory.current_bot_request = nil
            handle_web_inventory_failure(botName, 'coroutine_error')
            return false
        end
        return true
    end

    if BotInventory.current_bot_request == botName and BotInventory.bot_request_phase ~= 0 then 
        return false 
    end

    -- Start request without destroying existing cache; track capture count for this request
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
    if BotInventory.current_bot_request and BotInventory.bot_request_start_time then
        local elapsed = os.time() - BotInventory.bot_request_start_time
        local botName = BotInventory.current_bot_request
        if elapsed >= 10 then
            print(string.format("[BotInventory] Timeout waiting for inventory from %s", botName))
            -- Notify skip system of failure if available
            if BotInventory.onBotFailure then
                BotInventory.onBotFailure(botName, "Timeout waiting for inventory")
            end
            BotInventory.current_bot_request = nil
            BotInventory.bot_request_start_time = nil
            BotInventory.bot_request_phase = 0
            BotInventory.spawn_issued_time = nil
            BotInventory.target_issued_time = nil
            return
        end
        if (BotInventory._capture_count[botName] or 0) > 0 then
            -- Check for mismatches with previously cached data
            local oldData = nil
            local newData = BotInventory.bot_inventories[botName]
            
            -- Try to get old data from database first
            if db and db.load_all then
                local dbData = db.load_all() or {}
                oldData = dbData[botName]
            end
            
            -- Compare and detect mismatches
            if oldData and newData then
                local mismatches = BotInventory.compareInventoryData(botName, oldData, newData)
                if #mismatches > 0 then
                    print(string.format("[BotInventory] Detected %d mismatched item(s) for %s, queueing for scan", #mismatches, botName))
                    
                    -- Queue mismatched items for scanning if scan callback is available
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
            
            -- Persist to SQLite before clearing request state
            local meta = BotInventory.bot_list_capture_set and BotInventory.bot_list_capture_set[botName] or nil
            local ok, err = db.save_bot_inventory(botName, BotInventory.bot_inventories[botName], meta)
            if not ok then
                print(string.format("[BotInventory][DB] Failed to save inventory for %s: %s", botName, tostring(err)))
            else
                --print(string.format("[BotInventory][DB] Saved inventory for %s", botName))
            end

            --print(string.format("[BotInventory] Successfully captured inventory for %s (%d items)", botName, #BotInventory.bot_inventories[botName].equipped))
            BotInventory.current_bot_request = nil
            BotInventory._capture_count[botName] = 0
            BotInventory.bot_request_start_time = nil
            BotInventory.bot_request_phase = 0
            BotInventory.spawn_issued_time = nil
            BotInventory.target_issued_time = nil
            BotInventory.invlist_issued_time = nil
            return
        end
    end

    if not BotInventory.current_bot_request then
        return
    end

    local botName = BotInventory.current_bot_request

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
            print(string.format("[BotInventory DEBUG] Failed to target %s after 3 seconds. Aborting.", botName))
            -- Notify skip system of failure if available
            if BotInventory.onBotFailure then
                BotInventory.onBotFailure(botName, "Failed to target after 3 seconds")
            end
            BotInventory.bot_request_phase = 0
            BotInventory.current_bot_request = nil
            BotInventory.spawn_issued_time = nil
            BotInventory.target_issued_time = nil
            BotInventory.invlist_issued_time = nil
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
                print(string.format("[BotInventory][DB] Failed to persist after unequip for %s: %s", botName, tostring(err)))
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

    if BotInventory._web_botlist_coroutine and coroutine.status(BotInventory._web_botlist_coroutine) ~= 'dead' then
        local ok, err = coroutine.resume(BotInventory._web_botlist_coroutine)
        if not ok then
            print(string.format('[BotInventory] Web bot list coroutine error: %s', tostring(err)))
            handle_web_botlist_failure('coroutine_error')
        end
    end

    if BotInventory._web_bot_inventory_coroutines then
        local toRemove = {}
        for botName, co in pairs(BotInventory._web_bot_inventory_coroutines) do
            if coroutine.status(co) == 'dead' then
                table.insert(toRemove, botName)
            else
                local ok, err = coroutine.resume(co)
                if not ok then
                    print(string.format('[BotInventory] Web inventory coroutine error for %s: %s', tostring(botName), tostring(err)))
                    handle_web_inventory_failure(botName, 'coroutine_error')
                    table.insert(toRemove, botName)
                end
            end
        end
        for _, botName in ipairs(toRemove) do
            BotInventory._web_bot_inventory_coroutines[botName] = nil
            if BotInventory.current_bot_request == botName then
                BotInventory.current_bot_request = nil
            end
        end
    end

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
    if not botName or slotID == nil then return false, 'bad args' end

    -- Ensure bot cache exists
    BotInventory.bot_inventories[botName] = BotInventory.bot_inventories[botName] or {
        name = botName,
        equipped = {},
        bags = {},
        bank = {},
    }

    local eq = BotInventory.bot_inventories[botName].equipped

    local newItem = {
            name = itemName or 'Item',
            slotid = tonumber(slotID),
            slotname = slotName or tostring(slotID),
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
            oldBySlot[tonumber(item.slotid)] = item
        end
    end
    
    -- Index new items by slot ID
    for _, item in ipairs(newData.equipped) do
        if item.slotid then
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
            needsScan = (not newItem.ac or tonumber(newItem.ac) == 0) and
                       (not newItem.hp or tonumber(newItem.hp) == 0) and
                       (not newItem.mana or tonumber(newItem.mana) == 0) and
                       (not newItem.damage or tonumber(newItem.damage) == 0) and
                       (not newItem.delay or tonumber(newItem.delay) == 0)
            reason = "new item with missing stats"
        elseif oldItem.name ~= newItem.name or oldItem.itemID ~= newItem.itemID then
            -- Different item in the same slot
            needsScan = (not newItem.ac or tonumber(newItem.ac) == 0) and
                       (not newItem.hp or tonumber(newItem.hp) == 0) and
                       (not newItem.mana or tonumber(newItem.mana) == 0) and
                       (not newItem.damage or tonumber(newItem.damage) == 0) and
                       (not newItem.delay or tonumber(newItem.delay) == 0)
            reason = string.format("item changed from '%s' to '%s'", oldItem.name or "unknown", newItem.name or "unknown")
        else
            -- Same item, check for stat mismatches
            local oldAC = tonumber(oldItem.ac) or 0
            local oldHP = tonumber(oldItem.hp) or 0
            local oldMana = tonumber(oldItem.mana) or 0
            local newAC = tonumber(newItem.ac) or 0
            local newHP = tonumber(newItem.hp) or 0
            local newMana = tonumber(newItem.mana) or 0
            
            -- If old item had stats but new item doesn't, or stats changed significantly
            local oldDamage = tonumber(oldItem.damage) or 0
            local oldDelay = tonumber(oldItem.delay) or 0
            local newDamage = tonumber(newItem.damage) or 0
            local newDelay = tonumber(newItem.delay) or 0
            
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
    if BotInventory.initialized then return true end
    
    print('[BotInventory DEBUG] HTTP system initialized using socket.http')

    mq.event("GetBotList", "Bot #1# #*# #2# is a Level #3# #4# #5# #6# owned by You.#*", BotInventory.getBotListEvent)
    mq.event("BotInventory", "Slot #1# (#2#) #*#", displayBotInventory, { keepLinks = true })
    mq.event("BotUnequip", "#1# unequips #2# from slot #3#", displayBotUnequipResponse)

    -- Initialize database and pre-load prior state
    local ok, err = db.init()
    if not ok then
        print(string.format("[BotInventory][DB] Initialization failed: %s", tostring(err)))
    else
        local loaded = db.load_all() or {}
        for name, data in pairs(loaded) do
            BotInventory.bot_inventories[name] = data
            -- Seed capture set so UI can list bots immediately
            if not BotInventory.bot_list_capture_set[name] then
                BotInventory.bot_list_capture_set[name] = { Name = name }
            end
        end
        print(string.format("[BotInventory][DB] Loaded %d bot(s) from persistence", (function(t) local c=0 for _ in pairs(t) do c=c+1 end return c end)(loaded)))
    end

    print("[BotInventory] Bot inventory system initialized")
    
    BotInventory.cached_bot_list = {}
    BotInventory.initialized = true
    return true
end

return BotInventory
