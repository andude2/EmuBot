local mq = require('mq')
local ok_actors, actors = pcall(require, 'actors')

local M = {}

local MAILBOX_NAME = 'emubot_presence'

local state = {
    entries = {},
    initialized = false,
    mailbox = nil,
    actor_registered = false,
    my_name = nil,
    my_server = nil,
    stale_timeout = 15,
    cleanup_interval = 5,
    last_cleanup = 0,
    heartbeat_interval = 5,
    last_heartbeat = 0,
    data_provider = nil,
    data_handler = nil,
    request_handler = nil,
}

local function now()
    return os.time()
end

local function canonical(name)
    if not name or name == '' then return nil end
    return string.lower(name)
end

local function record(name, server)
    if not name or name == '' then return end
    local key = canonical(name)
    if not key then return end
    local entry = state.entries[key]
    if not entry then
        entry = {}
        state.entries[key] = entry
    end
    entry.name = name
    entry.server = server or entry.server or state.my_server or ''
    entry.last_seen = now()
end

local function handle_peer_status(message)
    local ok, content = pcall(message)
    if not ok or type(content) ~= 'table' then return end
    local name = content.name or content.character or content.owner or content.from or content.peer
    if not name or name == '' then return end
    local server = content.server or content.server_name or content.serverName
    if state.my_server and state.my_server ~= '' and server and server ~= '' and server ~= state.my_server then
        return
    end
    record(name, server)
    if content.request then
        local targetName = content.target
        if targetName and state.my_name and targetName:lower() == state.my_name:lower() then
            if state.request_handler then
                pcall(state.request_handler, name, content.request)
            end
        end
        return
    end
    if state.my_name and name == state.my_name and (not server or server == state.my_server) then
        return
    end
    if state.data_handler and (content.bot_list or content.bot_inventory or content.botList or content.botInventory) then
        local snapshot = {
            bot_list = content.bot_list or content.botList,
            bot_inventory = content.bot_inventory or content.botInventory,
        }
        pcall(state.data_handler, name, snapshot)
    end
end

local function broadcast_presence(force)
    if not ok_actors or not actors or not state.actor_registered then return end
    if not state.my_name or state.my_name == '' then return end
    local ts = now()
    if not force and ts - state.last_heartbeat < state.heartbeat_interval then return end
    state.last_heartbeat = ts
    local payload = {
        name = state.my_name,
        server = state.my_server,
        timestamp = ts,
    }
    if state.data_provider then
        local ok, data = pcall(state.data_provider)
        if ok and type(data) == 'table' then
            payload.bot_list = data.bot_list or data.botList
            payload.bot_inventory = data.bot_inventory or data.botInventory
        end
    end
    actors.send({mailbox = MAILBOX_NAME}, payload)
end

local function cleanup()
    local ts = now()
    if ts - state.last_cleanup < state.cleanup_interval then return end
    state.last_cleanup = ts
    for key, entry in pairs(state.entries) do
        if entry and entry.name and canonical(entry.name) == canonical(state.my_name) then
            entry.last_seen = ts
        elseif entry and entry.last_seen and ts - entry.last_seen > state.stale_timeout then
            state.entries[key] = nil
        end
    end
end

function M.init()
    if state.initialized then return true end
    state.my_name = mq.TLO.Me.CleanName() or mq.TLO.Me.Name() or ''
    state.my_server = mq.TLO.EverQuest.Server() or ''
    if state.my_name and state.my_name ~= '' then
        record(state.my_name, state.my_server)
    end
    if ok_actors then
        local ok, mailbox = pcall(function() return actors.register(MAILBOX_NAME, handle_peer_status) end)
        if ok and mailbox then
            state.mailbox = mailbox
            state.actor_registered = true
        end
    end
    state.initialized = true
    state.last_cleanup = now()
    broadcast_presence(true)
    return true
end

local function ensure_init()
    if not state.initialized then
        M.init()
    end
end

function M.process()
    if not state.initialized then return end
    cleanup()
    broadcast_presence(false)
end

function M.set_data_provider(fn)
    if type(fn) == 'function' then
        state.data_provider = fn
    else
        state.data_provider = nil
    end
end

function M.set_remote_data_handler(fn)
    if type(fn) == 'function' then
        state.data_handler = fn
    else
        state.data_handler = nil
    end
end

function M.set_request_handler(fn)
    if type(fn) == 'function' then
        state.request_handler = fn
    else
        state.request_handler = nil
    end
end

function M.is_connected(name)
    if not name or name == '' then return false end
    ensure_init()
    local key = canonical(name)
    if not key then return false end
    local self_key = canonical(state.my_name)
    if self_key and key == self_key then
        record(state.my_name, state.my_server)
        return true
    end
    local entry = state.entries[key]
    if not entry then return false end
    local ts = now()
    if not entry.last_seen or ts - entry.last_seen <= state.stale_timeout then
        return true
    end
    state.entries[key] = nil
    return false
end

function M.get_connected_players()
    ensure_init()
    cleanup()
    local ts = now()
    local results = {}
    local self_key = canonical(state.my_name)
    local has_self = false
    for key, entry in pairs(state.entries) do
        if entry and entry.name and entry.last_seen and ts - entry.last_seen <= state.stale_timeout then
            table.insert(results, entry.name)
            if self_key and key == self_key then
                has_self = true
            end
        end
    end
    if not has_self and state.my_name and state.my_name ~= '' then
        table.insert(results, state.my_name)
    end
    table.sort(results, function(a, b)
        return tostring(a):lower() < tostring(b):lower()
    end)
    return results
end

function M.set_stale_timeout(seconds)
    local value = tonumber(seconds)
    if value and value > 0 then
        state.stale_timeout = value
    end
end

function M.set_cleanup_interval(seconds)
    local value = tonumber(seconds)
    if value and value > 0 then
        state.cleanup_interval = value
    end
end

local function normalize_bot_list(bots)
    local list = {}
    if type(bots) == 'table' then
        for _, bot in ipairs(bots) do
            if bot and type(bot) == 'string' and bot ~= '' then
                table.insert(list, bot)
            end
        end
    elseif type(bots) == 'string' and bots ~= '' then
        table.insert(list, bots)
    end
    return list
end

function M.send_request(target, payload)
    if not target or target == '' or not payload then return false end
    ensure_init()
    if not ok_actors or not actors or not state.actor_registered then return false end
    local message = {
        name = state.my_name,
        server = state.my_server,
        target = target,
        request = payload,
    }
    actors.send({mailbox = MAILBOX_NAME}, message)
    return true
end

function M.request_remote_refresh(target, bots)
    local list = normalize_bot_list(bots)
    if not target or target == '' or #list == 0 then return false end
    local payload = {
        type = 'refresh_bots',
        bots = list,
    }
    return M.send_request(target, payload)
end

function M.request_remote_spawn(target, bots)
    local list = normalize_bot_list(bots)
    if not target or target == '' or #list == 0 then return false end
    local payload = {
        type = 'spawn_for_raid',
        bots = list,
    }
    return M.send_request(target, payload)
end

return M
