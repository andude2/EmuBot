-- emubot/modules/bot_groups.lua
-- Bot group management system for spawning and inviting groups of bots

local mq = require('mq')
local db = require('EmuBot.modules.db')
local bot_inventory = require('EmuBot.modules.bot_inventory')

local M = {}

-- State
M.groups = {}
M.selectedGroup = nil
M.editingGroup = nil
M.newGroupName = ""
M.newGroupDescription = ""
M.groupOperationInProgress = false
M.operationStatus = ""
-- internal tick-based throttle for fast, safe invites
M._tick = 0
M._lastInviteTick = 0
M._inviteTickInterval = 3 -- ~150ms when main loop runs every 50ms

local function printf(fmt, ...)
    if mq.printf then mq.printf(fmt, ...) else print(string.format(fmt, ...)) end
end

local function is_bot_spawned(name)
    local s = mq.TLO.Spawn(string.format('= %s', name))
    return s and s.ID and s.ID() and s.ID() > 0
end

local function target_bot(name)
    local s = mq.TLO.Spawn(string.format('= %s', name))
    if s and s.ID and s.ID() and s.ID() > 0 then
        mq.cmdf('/target id %d', s.ID())
        return true
    end
    mq.cmdf('/target "%s"', name)
    return true
end

-- Load all groups from database
function M.refresh_groups()
    if not db or not db.get_groups_with_members then
        M.groups = {}
        return
    end
    
    M.groups = db.get_groups_with_members()
    printf('[EmuBot] Loaded %d bot group(s)', #M.groups)
end

-- Create a new group
function M.create_group(name, description)
    if not name or name == "" then
        return false, "Group name cannot be empty"
    end
    
    local ok, result = db.create_group(name, description)
    if ok then
        printf('[EmuBot] Created new bot group: %s', name)
        M.refresh_groups()
        return true, result
    else
        printf('[EmuBot] Failed to create group: %s', tostring(result))
        return false, result
    end
end

-- Delete a group
function M.delete_group(groupId)
    if not groupId then
        return false, "Group ID required"
    end
    
    local ok, err = db.delete_group(groupId)
    if ok then
        printf('[EmuBot] Deleted bot group')
        M.refresh_groups()
        if M.selectedGroup and M.selectedGroup.id == groupId then
            M.selectedGroup = nil
        end
        return true
    else
        printf('[EmuBot] Failed to delete group: %s', tostring(err))
        return false, err
    end
end

-- Update a group
function M.update_group(groupId, name, description)
    if not groupId or not name or name == "" then
        return false, "Group ID and name required"
    end
    
    local ok, err = db.update_group(groupId, name, description)
    if ok then
        printf('[EmuBot] Updated bot group: %s', name)
        M.refresh_groups()
        return true
    else
        printf('[EmuBot] Failed to update group: %s', tostring(err))
        return false, err
    end
end

-- Add bot to group
function M.add_bot_to_group(groupId, botName)
    if not groupId or not botName then
        return false, "Group ID and bot name required"
    end
    
    local ok, err = db.add_bot_to_group(groupId, botName)
    if ok then
        printf('[EmuBot] Added %s to group', botName)
        M.refresh_groups()
        return true
    else
        printf('[EmuBot] Failed to add bot to group: %s', tostring(err))
        return false, err
    end
end

-- Remove bot from group
function M.remove_bot_from_group(groupId, botName)
    if not groupId or not botName then
        return false, "Group ID and bot name required"
    end
    
    local ok, err = db.remove_bot_from_group(groupId, botName)
    if ok then
        printf('[EmuBot] Removed %s from group', botName)
        M.refresh_groups()
        return true
    else
        printf('[EmuBot] Failed to remove bot from group: %s', tostring(err))
        return false, err
    end
end

-- Spawn all bots in a group
function M.spawn_group(groupId)
    local group = nil
    for _, g in ipairs(M.groups) do
        if g.id == groupId then
            group = g
            break
        end
    end
    
    if not group then
        return false, "Group not found"
    end
    
    if not group.members or #group.members == 0 then
        return false, "Group has no members"
    end
    
    printf('[EmuBot] Spawning group "%s" (%d bots)', group.name, #group.members)
    
    for _, member in ipairs(group.members) do
        local botName = member.bot_name
        if not is_bot_spawned(botName) then
            mq.cmdf('/say ^spawn %s', botName)
            printf('[EmuBot] Spawning %s', botName)
        else
            printf('[EmuBot] %s already spawned', botName)
        end
    end
    
    return true
end

-- Invite all bots in a group to the player's group
function M.invite_group(groupId)
    local group = nil
    for _, g in ipairs(M.groups) do
        if g.id == groupId then
            group = g
            break
        end
    end
    
    if not group then
        return false, "Group not found"
    end
    
    if not group.members or #group.members == 0 then
        return false, "Group has no members"
    end
    
    printf('[EmuBot] Inviting group "%s" (%d bots)', group.name, #group.members)
    
    for _, member in ipairs(group.members) do
        local botName = member.bot_name
        if is_bot_spawned(botName) then
            -- Invite directly by name to avoid target hops
            mq.cmdf('/invite %s', botName)
            printf('[EmuBot] Inviting %s to group', botName)
            mq.delay(100)
        else
            printf('[EmuBot] %s not spawned, cannot invite', botName)
        end
    end
    
    return true
end

-- Spawn and invite group (combined operation) - Non-blocking version
function M.spawn_and_invite_group(groupId)
    local group = nil
    for _, g in ipairs(M.groups) do
        if g.id == groupId then
            group = g
            break
        end
    end
    
    if not group then
        return false, "Group not found"
    end
    
    if not group.members or #group.members == 0 then
        return false, "Group has no members"
    end
    
    M.groupOperationInProgress = true
    M.operationStatus = string.format('Spawning and inviting group "%s"...', group.name)
    
    printf('[EmuBot] Spawning and inviting group "%s" (%d bots)', group.name, #group.members)
    
    -- First, spawn all bots that need spawning
    local spawnedBots = {}
    local alreadySpawned = {}
    
    for _, member in ipairs(group.members) do
        local botName = member.bot_name
        if not is_bot_spawned(botName) then
            mq.cmdf('/say ^spawn %s', botName)
            printf('[EmuBot] Spawning %s', botName)
            table.insert(spawnedBots, botName)
        else
            printf('[EmuBot] %s already spawned', botName)
            table.insert(alreadySpawned, botName)
        end
    end
    
    -- Prepare invitation state; invitations will begin immediately and
    -- proceed as soon as each bot appears in the spawn list.
    M._inviteGroup = {
        groupId = groupId,
        groupName = group.name,
        botsToInvite = {},
        currentBotIndex = 1,
        attempts = {},
    }
    
    -- Add already spawned bots to invite list immediately
    for _, botName in ipairs(alreadySpawned) do
        table.insert(M._inviteGroup.botsToInvite, botName)
    end
    
    -- Add newly spawned bots to invite list
    for _, botName in ipairs(spawnedBots) do
        table.insert(M._inviteGroup.botsToInvite, botName)
    end
    
    return true
end

-- Process pending invitations (called from main loop)
function M.process_invitations()
    if not M._inviteGroup then return end

    -- tick forward; main loop calls every ~50ms
    M._tick = (M._tick or 0) + 1

    local invite = M._inviteGroup

    -- Finished?
    if invite.currentBotIndex > #invite.botsToInvite then
        M.groupOperationInProgress = false
        M.operationStatus = string.format('Completed spawning and inviting group "%s"', invite.groupName)
        M._inviteGroup = nil
        M.operationStatus = ""
        return
    end

    -- Throttle: ensure minimal spacing between invites
    if (M._tick - (M._lastInviteTick or 0)) < (M._inviteTickInterval or 3) then
        return
    end

    local botName = invite.botsToInvite[invite.currentBotIndex]
    if is_bot_spawned(botName) then
        -- Direct invite by name for speed and reliability
        mq.cmdf('/invite %s', botName)
        printf('[EmuBot] Inviting %s to group', botName)
        M._lastInviteTick = M._tick
        invite.currentBotIndex = invite.currentBotIndex + 1
    else
        -- Not spawned yet; wait and re-check next tick without advancing index
        -- Optionally track attempts to avoid infinite waiting (e.g., after ~10s)
        local a = (invite.attempts[botName] or 0) + 1
        invite.attempts[botName] = a
        -- After ~200 attempts (~10s at 50ms/tick), skip and move on
        if a >= 200 then
            printf('[EmuBot] %s did not appear in time, skipping invite', botName)
            invite.currentBotIndex = invite.currentBotIndex + 1
        end
    end
end

-- Get group status (how many spawned, etc.)
function M.get_group_status(groupId)
    local group = nil
    for _, g in ipairs(M.groups) do
        if g.id == groupId then
            group = g
            break
        end
    end
    
    if not group or not group.members then
        return { total = 0, spawned = 0, percentage = 0 }
    end
    
    local total = #group.members
    local spawned = 0
    
    for _, member in ipairs(group.members) do
        if is_bot_spawned(member.bot_name) then
            spawned = spawned + 1
        end
    end
    
    local percentage = total > 0 and math.floor((spawned / total) * 100) or 0
    
    return {
        total = total,
        spawned = spawned,
        percentage = percentage
    }
end

-- Check if bot is in any group
function M.is_bot_in_group(botName)
    for _, group in ipairs(M.groups) do
        if group.members then
            for _, member in ipairs(group.members) do
                if member.bot_name == botName then
                    return true, group
                end
            end
        end
    end
    return false, nil
end

-- Initialize the module
function M.init()
    M.refresh_groups()
    return true
end

return M
