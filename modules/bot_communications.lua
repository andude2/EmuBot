local mq = require('mq')
local actors = require('actors')
local json = require('dkjson')

local bot_communications = {}

-- Debug: Check if modules loaded
if not actors then
    print('[EmuBot] ERROR: actors module not found!')
else
    print('[EmuBot] actors module loaded successfully')
end

if not json then
    print('[EmuBot] ERROR: json module not found!')
else
    print('[EmuBot] json module loaded successfully')
end

-- Mailbox names
local MAILBOX_NAME = "emubot_data"
local COMMAND_MAILBOX = "emubot_command"

-- Peer data storage
bot_communications.peer_data = {}
bot_communications.peer_presence = {}
bot_communications.last_heartbeat = {}

-- Local data cache
bot_communications.local_bot_data = {}
bot_communications.local_character_name = mq.TLO.Me.Name() or "Unknown"

-- Configuration
bot_communications.heartbeat_interval = 30 -- seconds
bot_communications.data_broadcast_interval = 60 -- seconds
bot_communications.peer_timeout = 120 -- seconds (2 minutes)

-- Mailbox actors
local data_actor = nil
local command_actor = nil

local function printf(fmt, ...)
    if mq.printf then
        mq.printf(fmt, ...)
    else
        print(string.format(fmt, ...))
    end
end

-- Initialize the mailbox system
function bot_communications.init()
    printf('[EmuBot] Initializing communications mailbox system...')

    -- Register data mailbox for receiving peer bot data
    local ok_data, result_data = pcall(function()
        return actors.register(MAILBOX_NAME, bot_communications.handleDataMessage)
    end)

    if ok_data and result_data then
        data_actor = result_data
        printf('[EmuBot] Data mailbox registered: %s', MAILBOX_NAME)
    else
        printf('[EmuBot] Failed to register data mailbox: %s', tostring(result_data))
        return false
    end

    -- Register command mailbox for receiving commands
    local ok_command, result_command = pcall(function()
        return actors.register(COMMAND_MAILBOX, bot_communications.handleCommandMessage)
    end)

    if ok_command and result_command then
        command_actor = result_command
        printf('[EmuBot] Command mailbox registered: %s', COMMAND_MAILBOX)
    else
        printf('[EmuBot] Failed to register command mailbox: %s', tostring(result_command))
        return false
    end

    -- Start heartbeat timer
    bot_communications.last_heartbeat_time = os.time()
    bot_communications.last_broadcast_time = os.time()

    printf('[EmuBot] Communications system initialized successfully')
    return true
end

-- Handle incoming data messages from peers
function bot_communications.handleDataMessage(message)
    if not message then return end

    -- Message is a function that returns the raw JSON string
    local raw = message()
    if not raw then return end

    -- Decode the JSON string
    local messageData, pos, err = json.decode(raw)
    if not messageData or type(messageData) ~= "table" then
        printf('[EmuBot] Invalid data message: %s', tostring(err or raw))
        return
    end

    local sender = messageData.sender
    if not sender then return end

    -- Update peer presence
    bot_communications.peer_presence[sender] = os.time()

    -- Handle different message types
    if messageData.type == "bot_data" then
        bot_communications.peer_data[sender] = messageData.bots or {}
        printf('[EmuBot] Received bot data from %s (%d bots)', sender, #messageData.bots)
    elseif messageData.type == "heartbeat" then
        -- Heartbeat received, presence already updated
    elseif messageData.type == "request_data" then
        -- Peer is requesting our data, send it
        bot_communications.broadcastLocalData()
    end
end

-- Handle incoming command messages
function bot_communications.handleCommandMessage(message)
    if not message then return end

    -- Message is a function that returns the raw JSON string
    local raw = message()
    if not raw then return end

    -- Decode the JSON string
    local commandData, pos, err = json.decode(raw)
    if not commandData or type(commandData) ~= "table" then
        printf('[EmuBot] Invalid command message: %s', tostring(err or raw))
        return
    end

    if commandData.type == "request_data" then
        -- Peer is requesting our data, send it
        bot_communications.broadcastLocalData()
    end
end

-- Send a command (broadcast to all peers)
function bot_communications.sendCommand(command)
    if not command_actor then
        printf('[EmuBot] Cannot send command - no command actor')
        return false
    end

    local commandJson = json.encode(command)
    if not commandJson then
        printf('[EmuBot] Failed to encode command data')
        return false
    end

    local ok, err = pcall(function()
        command_actor:send({ mailbox = COMMAND_MAILBOX }, commandJson)
    end)

    if not ok then
        printf('[EmuBot] Failed to send command: %s', tostring(err))
        return false
    end

    return true
end

-- Broadcast local bot data to all peers
function bot_communications.broadcastLocalData()
    if not data_actor then
        printf('[EmuBot] Cannot broadcast - no data actor')
        return false
    end

    -- Use the stored local bot data
    local botData = bot_communications.local_bot_data or {}

    local messageData = {
        type = "bot_data",
        sender = bot_communications.local_character_name,
        bots = botData,
        timestamp = os.time()
    }

    local messageJson = json.encode(messageData)
    if not messageJson then
        printf('[EmuBot] Failed to encode message data')
        return false
    end

    -- Broadcast to all peers
    local ok, err = pcall(function()
        actors.send({ mailbox = MAILBOX_NAME }, messageJson)
    end)

    if ok then
        printf('[EmuBot] Broadcasted local bot data (%d bots)', #botData)
        bot_communications.last_broadcast_time = os.time()
    else
        printf('[EmuBot] Failed to broadcast bot data: %s', tostring(err))
        return false
    end

    return true
end

-- Send heartbeat to maintain presence
function bot_communications.sendHeartbeat()
    if not data_actor then
        printf('[EmuBot] Cannot send heartbeat - no data actor')
        return false
    end

    local messageData = {
        type = "heartbeat",
        sender = bot_communications.local_character_name,
        timestamp = os.time()
    }

    local messageJson = json.encode(messageData)
    if not messageJson then
        printf('[EmuBot] Failed to encode heartbeat data')
        return false
    end

    local ok, err = pcall(function()
        actors.send({ mailbox = MAILBOX_NAME }, messageJson)
    end)

    if ok then
        printf('[EmuBot] Heartbeat sent')
        bot_communications.last_heartbeat_time = os.time()
    else
        printf('[EmuBot] Failed to send heartbeat: %s', tostring(err))
        return false
    end

    return true
end

-- Collect local bot data for broadcasting
function bot_communications.collectLocalBotData(bot_inventory_module)
    local botData = {}

    -- Get bot data from bot_inventory if available
    if bot_inventory_module and bot_inventory_module.getAllBots then
        local botNames = bot_inventory_module.getAllBots() or {}
        for _, botName in ipairs(botNames) do
            local botInfo = bot_inventory_module.getBotInventory and bot_inventory_module.getBotInventory(botName)
            if botInfo and botInfo.equipped then
                table.insert(botData, {
                    name = botName,
                    equipped = botInfo.equipped or {},
                    level = botInfo.level,
                    class = botInfo.class,
                    last_updated = os.time()
                })
            end
        end
    end

    return botData
end

-- Update local bot data (called by main EmuBot script)
function bot_communications.updateLocalBotData(bot_inventory_module)
    local old_count = bot_communications.local_bot_data and #bot_communications.local_bot_data or 0
    bot_communications.local_bot_data = bot_communications.collectLocalBotData(bot_inventory_module)
    local new_count = bot_communications.local_bot_data and #bot_communications.local_bot_data or 0

    if new_count ~= old_count then
        printf('[EmuBot] Local bot data updated: %d bots', new_count)
    end
end

-- Request data from peers (broadcast request)
function bot_communications.requestPeerData()
    return bot_communications.sendCommand({ type = "request_data" })
end

-- Get list of active peers
function bot_communications.getActivePeers()
    local activePeers = {}
    local now = os.time()

    for peerName, lastSeen in pairs(bot_communications.peer_presence) do
        if now - lastSeen < bot_communications.peer_timeout then
            table.insert(activePeers, {
                name = peerName,
                last_seen = lastSeen,
                data = bot_communications.peer_data[peerName] or {}
            })
        end
    end

    return activePeers
end

-- Clean up old peer data
function bot_communications.cleanupOldPeers()
    local now = os.time()
    local removed = 0

    for peerName, lastSeen in pairs(bot_communications.peer_presence) do
        if now - lastSeen > bot_communications.peer_timeout then
            bot_communications.peer_data[peerName] = nil
            bot_communications.peer_presence[peerName] = nil
            removed = removed + 1
        end
    end

    if removed > 0 then
        printf('[EmuBot] Cleaned up %d inactive peers', removed)
    end

    return removed
end

-- Main update function to be called periodically
function bot_communications.update()
    local now = os.time()

    -- Send heartbeat if needed
    if now - (bot_communications.last_heartbeat_time or 0) >= bot_communications.heartbeat_interval then
        bot_communications.sendHeartbeat()
    end

    -- Broadcast data if needed
    if now - (bot_communications.last_broadcast_time or 0) >= bot_communications.data_broadcast_interval then
        bot_communications.broadcastLocalData()
    end

    -- Clean up old peers occasionally
    if math.fmod(now, 60) == 0 then -- Every minute
        local cleaned = bot_communications.cleanupOldPeers()
        if cleaned > 0 then
            printf('[EmuBot] Cleaned up %d old peers', cleaned)
        end
    end
end

-- Shutdown the communications system
function bot_communications.shutdown()
    printf('[EmuBot] Shutting down communications system...')

    if data_actor then
        pcall(function() data_actor:close() end)
        data_actor = nil
    end

    if command_actor then
        pcall(function() command_actor:close() end)
        command_actor = nil
    end

    bot_communications.peer_data = {}
    bot_communications.peer_presence = {}

    printf('[EmuBot] Communications system shut down')
end

return bot_communications