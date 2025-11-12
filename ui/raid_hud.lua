-- EmuBot Raid HUD - Floating display for raid members with HPS tracking
-- Provides compact, floating UI showing raid member names/classes and HPS data
-- Supports alphabetical, raid group, and class-based sorting

local mq = require('mq')
local ImGui = require('ImGui')
local Icons = require('mq.icons')
local config_paths = require('config')

-- Optional JSON for saving settings
local has_json, json = pcall(require, 'dkjson')

local M = {}

-- State and configuration
local state = {
    show = false,
    showSettings = false,
    showToggleButton = true,
}

local config = {
    window = {
        opacity = 0.9,
        bg = {r=0.05, g=0.05, b=0.05, a=0.95},
        border = {r=0.3, g=0.3, b=0.3, a=0.8},
        use_custom_bg = true,
        padding = 6,
        rounding = 8,
        width = 300,
        height = 400,
        hide_title_bar = false,
    },
    display = {
        sort_mode = "alphabetical", -- "alphabetical", "raid_group", "class"
        show_class_names = false,
        show_name_with_class = false, -- Show "Name (Class)" format
        compact_mode = false,
        max_entries = 72, -- Max raid size
        refresh_rate = 1.0, -- Seconds between updates
        hps_window = 10.0, -- Seconds for HPS calculation
        show_mana = false,
        show_distance = false,
        show_offline = false,
        name_width = 120,
        mana_width = 60,
        distance_width = 70,
        class_width = 50,
        name_class_width = 160, -- Width for "Name (Class)" format
        auto_size = true, -- Enable auto-sizing
        min_window_height = 120,
        max_window_height = 800,
        line_spacing = 0, -- Extra spacing between lines
        -- Group layout options
        enable_group_layout = false, -- Enable multi-column group layout
        groups_per_row = 3, -- Number of groups per row (2-6)
        group_spacing = 10, -- Extra horizontal spacing between group columns
        grouping_method = "auto", -- "auto", "position", "eq_groups" - how to assign groups
        -- Separate group windows options
        separate_group_windows = false, -- Show each group in its own window
        max_groups_to_show = 6, -- Maximum number of group windows to show (1-12)
        group_window_spacing = 20, -- Vertical spacing between group windows
    },
    toggle_button = {
        enabled = true, -- Show the floating toggle button
        size = 50, -- Button size (matches EmuBot floating button size)
        opacity = 0.8, -- Button opacity
        pos_x = 50, -- Default X position
        pos_y = 50, -- Default Y position
        text = "R", -- Button text 
        lock_position = false, -- Lock button position to prevent dragging
    },
    colors = {
        online = {r=0.9, g=0.9, b=0.9, a=1.0},
        offline = {r=0.5, g=0.5, b=0.5, a=0.7},
        self = {r=0.3, g=0.9, b=0.3, a=1.0},
        tank = {r=0.6, g=0.6, b=1.0, a=1.0},
        healer = {r=0.3, g=1.0, b=0.3, a=1.0},
        dps = {r=1.0, g=0.7, b=0.3, a=1.0},
        header = {r=0.8, g=0.8, b=0.3, a=1.0},
    },
}

-- Raid data storage
local raid_data = {
    members = {}, -- [name] = member_data
    last_update = 0,
    heal_events = {}, -- Circular buffer for heal tracking
    heal_index = 1,
    max_heal_events = 1000,
}

-- Member data structure
local function create_member_data(name)
    return {
        name = name,
        class = "Unknown",
        level = 0,
        group_number = 0,
        online = true,
        spawned = false,
        dead = false,
        current_hp = 0,
        max_hp = 0,
        current_mana = 0,
        max_mana = 0,
        hp_percent = 100,
        mana_percent = 0,
        distance = 0,
        zone = "",
        hps = 0,
        last_seen = os.time(),
        total_heals = 0,
        heal_timestamps = {}, -- For HPS calculation
    }
end

-- HPS tracking system
local function add_heal_event(healer_name, target_name, amount, timestamp)
    timestamp = timestamp or os.time()
    
    -- Add to global heal events (circular buffer)
    local event = {
        healer = healer_name,
        target = target_name,
        amount = amount,
        timestamp = timestamp,
    }
    
    raid_data.heal_events[raid_data.heal_index] = event
    raid_data.heal_index = raid_data.heal_index + 1
    if raid_data.heal_index > raid_data.max_heal_events then
        raid_data.heal_index = 1
    end
    
    -- Update healer's personal tracking
    if raid_data.members[healer_name] then
        local member = raid_data.members[healer_name]
        member.total_heals = member.total_heals + amount
        table.insert(member.heal_timestamps, {amount = amount, time = timestamp})
        
        -- Keep only recent heals within the HPS window
        local cutoff_time = timestamp - config.display.hps_window
        local filtered_heals = {}
        for _, heal in ipairs(member.heal_timestamps) do
            if heal.time >= cutoff_time then
                table.insert(filtered_heals, heal)
            end
        end
        member.heal_timestamps = filtered_heals
    end
end

local function calculate_hps(member_name)
    local member = raid_data.members[member_name]
    if not member or not member.heal_timestamps then return 0 end
    
    local now = os.time()
    local cutoff_time = now - config.display.hps_window
    local total_healing = 0
    local oldest_time = now
    
    for _, heal in ipairs(member.heal_timestamps) do
        if heal.time >= cutoff_time then
            total_healing = total_healing + heal.amount
            if heal.time < oldest_time then
                oldest_time = heal.time
            end
        end
    end
    
    local time_window = math.max(1, now - oldest_time)
    return math.floor(total_healing / time_window)
end

-- Class categorization and colors
local class_info = {
    ["Warrior"] = {abbrev = "WAR", category = "tank", color = config.colors.tank},
    ["Paladin"] = {abbrev = "PAL", category = "tank", color = config.colors.tank},
    ["Shadow Knight"] = {abbrev = "SHD", category = "tank", color = config.colors.tank},
    ["Shadowknight"] = {abbrev = "SHD", category = "tank", color = config.colors.tank},
    ["Cleric"] = {abbrev = "CLR", category = "healer", color = config.colors.healer},
    ["Druid"] = {abbrev = "DRU", category = "healer", color = config.colors.healer},
    ["Shaman"] = {abbrev = "SHM", category = "healer", color = config.colors.healer},
    ["Ranger"] = {abbrev = "RNG", category = "dps", color = config.colors.dps},
    ["Monk"] = {abbrev = "MNK", category = "dps", color = config.colors.dps},
    ["Bard"] = {abbrev = "BRD", category = "dps", color = config.colors.dps},
    ["Rogue"] = {abbrev = "ROG", category = "dps", color = config.colors.dps},
    ["Necromancer"] = {abbrev = "NEC", category = "dps", color = config.colors.dps},
    ["Wizard"] = {abbrev = "WIZ", category = "dps", color = config.colors.dps},
    ["Magician"] = {abbrev = "MAG", category = "dps", color = config.colors.dps},
    ["Enchanter"] = {abbrev = "ENC", category = "dps", color = config.colors.dps},
    ["Beastlord"] = {abbrev = "BST", category = "dps", color = config.colors.dps},
    ["Berserker"] = {abbrev = "BER", category = "dps", color = config.colors.dps},
}

local function get_class_info(class_name)
    if not class_name then return {abbrev = "UNK", category = "dps", color = config.colors.dps} end
    local upper_class = class_name:upper()
    
    for class, info in pairs(class_info) do
        if class:upper() == upper_class or class:upper():find(upper_class) then
            return info
        end
    end
    
    return {abbrev = "UNK", category = "dps", color = config.colors.dps}
end

-- Check if a class uses mana (non-mana classes: Warrior, Monk, Rogue, Berserker)
local function class_uses_mana(class_name)
    if not class_name then return false end
    local upper_class = class_name:upper()
    local non_mana_classes = {
        ["WARRIOR"] = true,
        ["WAR"] = true,
        ["MONK"] = true,
        ["MNK"] = true,
        ["ROGUE"] = true,
        ["ROG"] = true,
        ["BERSERKER"] = true,
        ["BER"] = true,
    }
    return not non_mana_classes[upper_class]
end

-- Normalize MQ truthy/falsey values to strict booleans
local function to_bool(v)
    local t = type(v)
    if t == 'boolean' then return v end
    if t == 'number' then return v ~= 0 end
    if t == 'string' then
        local s = v:lower()
        return s == 'true' or s == '1' or s == 'y' or s == 'yes'
    end
    return v and true or false
end

-- Organize members by groups for multi-column layout
local function organize_members_by_groups(members)
    local groups = {}
    
    for _, member in ipairs(members) do
        local group_num = member.raid_position_group or 1
        if not groups[group_num] then
            groups[group_num] = {}
        end
        table.insert(groups[group_num], member)
    end
    
    -- Convert to sorted array of groups
    local sorted_groups = {}
    for group_num, group_members in pairs(groups) do
        table.insert(sorted_groups, {
            number = group_num,
            members = group_members
        })
    end
    
    table.sort(sorted_groups, function(a, b) return a.number < b.number end)
    return sorted_groups
end

-- Forward declaration for inline cell renderer
local render_member_cells_inline

-- Render a single member row (helper function)
local function render_member_row(member)
    ImGui.TableNextRow()
    render_member_cells_inline(member)
end

-- Render member cells inline within the current row (does NOT advance the row)
render_member_cells_inline = function(member)
    -- Name column (always show raid name, not class)
    ImGui.TableNextColumn()
    
    local display_name
    if config.display.show_name_with_class then
        -- Show "Name (Class)" format
        local ci = get_class_info(member.class)
        local class_abbrev = (ci and ci.abbrev) or (member.class or "?")
        display_name = string.format("%s (%s)", member.name, class_abbrev)
    elseif config.display.show_class_names then
        -- Show just class abbreviation
        local ci = get_class_info(member.class)
        display_name = (ci and ci.abbrev) or (member.class or "?")
    else
        -- Show just name
        display_name = member.name
    end
    
    -- Choose color based on spawn/death status:
    -- - Red if not spawned or dead
    -- - Green if spawned/online
    -- - Gray if offline/unknown
    local color = config.colors.offline  -- Default gray for offline
    if member.is_self then
        color = config.colors.self  -- Keep self color
    elseif member.dead or not member.spawned then
        color = {r=1.0, g=0.2, b=0.2, a=1.0}  -- Red for dead or not spawned
    elseif member.spawned or member.online then
        color = {r=0.3, g=1.0, b=0.3, a=1.0}  -- Green for spawned/online
    end
    
    ImGui.TextColored(color.r, color.g, color.b, color.a, display_name)

    local leftClicked = ImGui.IsItemClicked and ImGui.IsItemClicked(ImGuiMouseButton.Left)
    if leftClicked then
        if member.spawned then
            local spawnLookup = member.name and string.format('= %s', member.name) or nil
            local spawn = spawnLookup and mq.TLO.Spawn(spawnLookup) or nil
            local targetFmt, targetArg
            if spawn and spawn.ID and spawn.ID() and spawn.ID() > 0 then
                targetFmt, targetArg = '/target id %d', spawn.ID()
            else
                targetFmt, targetArg = '/target "%s"', member.name or ''
            end

            if mq and mq.cmdf then
                mq.cmdf(targetFmt, targetArg)
            elseif mq and mq.cmd then
                mq.cmd(string.format(targetFmt, targetArg))
            end
        else
            if mq and mq.cmdf then
                mq.cmdf('/say ^spawn %s', member.name)
            elseif mq and mq.cmd then
                mq.cmd('/say ^spawn ' .. (member.name or ''))
            end
            -- Force a quick refresh next frame
            if raid_data then raid_data.last_update = 0 end
        end
    end
    
    -- HP% column with color coding (2nd column)
    ImGui.TableNextColumn()
    local hp_color = {r=0.9, g=0.9, b=0.9, a=1.0} -- white default
    if member.hp_percent < 25 then
        hp_color = {r=1.0, g=0.2, b=0.2, a=1.0} -- red
    elseif member.hp_percent < 50 then
        hp_color = {r=1.0, g=0.7, b=0.2, a=1.0} -- orange
    elseif member.hp_percent < 75 then
        hp_color = {r=1.0, g=1.0, b=0.3, a=1.0} -- yellow
    else
        hp_color = {r=0.3, g=1.0, b=0.3, a=1.0} -- green
    end
    
    ImGui.TextColored(hp_color.r, hp_color.g, hp_color.b, hp_color.a, 
                    string.format("%d%%", member.hp_percent))
    
    -- Mana column (3rd column)
    if config.display.show_mana then
        ImGui.TableNextColumn()
        if class_uses_mana(member.class) then
            if member.max_mana > 0 then
                local mana_color = {r=0.3, g=0.6, b=1.0, a=1.0} -- blue default
                if member.mana_percent < 25 then
                    mana_color = {r=1.0, g=0.2, b=0.2, a=1.0} -- red
                elseif member.mana_percent < 50 then
                    mana_color = {r=1.0, g=0.7, b=0.2, a=1.0} -- orange
                end
                ImGui.TextColored(mana_color.r, mana_color.g, mana_color.b, mana_color.a,
                                string.format("%d%%", member.mana_percent))
            else
                ImGui.TextColored(0.5, 0.5, 0.5, 0.7, "N/A")
            end
        else
            ImGui.TextColored(0.6, 0.6, 0.6, 1.0, "-")
        end
    end
    
    -- Distance column
    if config.display.show_distance then
        ImGui.TableNextColumn()
        if member.distance > 0 then
            local distance_text = string.format("%.0f", member.distance)
            local distance_color = {r=0.9, g=0.9, b=0.9, a=1.0} -- white default
            if member.distance > 200 then
                distance_color = {r=1.0, g=0.2, b=0.2, a=1.0} -- red for far
            elseif member.distance > 100 then
                distance_color = {r=1.0, g=0.7, b=0.2, a=1.0} -- orange for medium
            else
                distance_color = {r=0.3, g=1.0, b=0.3, a=1.0} -- green for close
            end
            ImGui.TextColored(distance_color.r, distance_color.g, distance_color.b, distance_color.a, distance_text)
        else
            ImGui.TextColored(0.5, 0.5, 0.5, 0.7, "-")
        end
    end
end

-- Data collection from MQ
local function update_raid_data()
    local now = os.time()
    if now - raid_data.last_update < config.display.refresh_rate then
        return
    end
    
    raid_data.last_update = now
    
    -- Get my name for self-identification
    local my_name = nil
    if mq and mq.TLO and mq.TLO.Me then
        local ok, name = pcall(function() return mq.TLO.Me.CleanName() or mq.TLO.Me.Name() end)
        if ok and name and name ~= '' then
            my_name = name
        end
    end
    
    -- Clear existing online status
    for name, member in pairs(raid_data.members) do
        member.online = false
    end
    
    -- Update from raid data
    local raid_count = 0
    local ok, count = pcall(function()
        return mq.TLO.Raid and mq.TLO.Raid.Members and tonumber(mq.TLO.Raid.Members()) or 0
    end)
    if ok and count then raid_count = count end
    
    if raid_count > 0 then
        -- We're in a raid, collect raid member data
        for i = 1, raid_count do
            local ok, member_tlo = pcall(function() return mq.TLO.Raid.Member(i) end)
            if ok and member_tlo then
                local name, class, level, group_num, current_hp, max_hp, zone
                
                -- Safely extract member data
                local current_mana, max_mana, distance, spawned, dead = 0, 0, 0, false, false
                pcall(function()
                    name = member_tlo.Name and member_tlo.Name() or member_tlo.CleanName and member_tlo.CleanName()
                    class = member_tlo.Class and member_tlo.Class()
                    level = tonumber(member_tlo.Level and member_tlo.Level() or 0)
                    group_num = tonumber(member_tlo.GroupNumber and member_tlo.GroupNumber() or 0)

                    -- Raw TLO fetches (nil if not available)
                    local hp_raw = member_tlo.CurrentHPs and member_tlo.CurrentHPs()
                    local maxhp_raw = member_tlo.MaxHPs and member_tlo.MaxHPs()
                    local mana_raw = member_tlo.CurrentMana and member_tlo.CurrentMana()
                    local maxmana_raw = member_tlo.MaxMana and member_tlo.MaxMana()
                    local dist_raw = member_tlo.Distance3D and member_tlo.Distance3D()

                    -- Numeric conversions with safe defaults
                    current_hp = tonumber(hp_raw or 0)
                    max_hp = tonumber(maxhp_raw or 0)
                    current_mana = tonumber(mana_raw or 0)
                    max_mana = tonumber(maxmana_raw or 0)
                    distance = tonumber(dist_raw or 0)

                    -- Spawned if any of the stat TLOs are available
                    spawned = (hp_raw ~= nil) or (maxhp_raw ~= nil) or (mana_raw ~= nil) or (maxmana_raw ~= nil) or (dist_raw ~= nil)

                    -- Dead only meaningful if spawned and we have HP data
                    dead = spawned and (current_hp == 0 and max_hp > 0)

                    zone = member_tlo.Zone and member_tlo.Zone()
                end)
                
                if name and name ~= '' then
                    if not raid_data.members[name] then
                        raid_data.members[name] = create_member_data(name)
                    end
                    
                    local member = raid_data.members[name]
                    member.online = true
                    member.class = class or member.class
                    member.level = level or member.level
                    member.group_number = group_num or member.group_number
                    
                    -- Assign group based on selected grouping method
                    if config.display.grouping_method == "eq_groups" then
                        -- Use EverQuest's actual group numbers only
                        member.raid_position_group = (group_num and group_num > 0) and group_num or 1
                    elseif config.display.grouping_method == "position" then
                        -- Always use position-based grouping (1-6 = Group 1, 7-12 = Group 2, etc.)
                        member.raid_position_group = math.ceil(i / 6)
                    else -- "auto" method
                        -- Use actual EQ group number if available, otherwise calculate position-based group
                        if group_num and group_num > 0 then
                            member.raid_position_group = group_num
                        else
                            -- Fallback: Calculate position-based raid group
                            member.raid_position_group = math.ceil(i / 6)
                        end
                    end
                    member.raid_position = i
                    member.current_hp = current_hp or member.current_hp
                    member.max_hp = max_hp or member.max_hp
                    member.current_mana = current_mana or member.current_mana
                    member.max_mana = max_mana or member.max_mana
                    member.distance = distance or member.distance
                    member.spawned = spawned
                    member.dead = dead
                    member.zone = zone or member.zone
                    member.last_seen = now
                    member.is_self = (name == my_name)
                    
                    -- Calculate HP percentage
                    if member.max_hp > 0 then
                        member.hp_percent = math.floor((member.current_hp / member.max_hp) * 100)
                    else
                        member.hp_percent = 100
                    end
                    
                    -- Calculate Mana percentage
                    if member.max_mana > 0 then
                        member.mana_percent = math.floor((member.current_mana / member.max_mana) * 100)
                    else
                        member.mana_percent = 0
                    end
                    
                    -- Update HPS
                    member.hps = calculate_hps(name)
                end
            end
        end
    else
        -- Check if we're in a group instead
        local group_count = 0
        local ok, count = pcall(function()
            return mq.TLO.Group and mq.TLO.Group.Members and tonumber(mq.TLO.Group.Members()) or 0
        end)
        if ok and count then group_count = count end
        
        if group_count > 0 then
            -- Include self
            if my_name then
                if not raid_data.members[my_name] then
                    raid_data.members[my_name] = create_member_data(my_name)
                end
                
                local self_member = raid_data.members[my_name]
                self_member.online = true
                self_member.is_self = true
                self_member.last_seen = now
                self_member.raid_position_group = 1  -- Self is always in "group 1" for group mode
                self_member.raid_position = 1
                
                -- Get self data
                pcall(function()
                    self_member.class = mq.TLO.Me.Class()
                    self_member.level = tonumber(mq.TLO.Me.Level())
                    self_member.current_hp = tonumber(mq.TLO.Me.CurrentHPs())
                    self_member.max_hp = tonumber(mq.TLO.Me.MaxHPs())
                    self_member.current_mana = tonumber(mq.TLO.Me.CurrentMana())
                    self_member.max_mana = tonumber(mq.TLO.Me.MaxMana())
                    self_member.distance = 0  -- Self distance is always 0
                    self_member.spawned = true  -- Self is always spawned
                    self_member.dead = (mq.TLO.Me.CurrentHPs() == 0)
                    self_member.zone = mq.TLO.Zone.ShortName()
                end)
                
                if self_member.max_hp > 0 then
                    self_member.hp_percent = math.floor((self_member.current_hp / self_member.max_hp) * 100)
                end
                
                if self_member.max_mana > 0 then
                    self_member.mana_percent = math.floor((self_member.current_mana / self_member.max_mana) * 100)
                end
                
                self_member.hps = calculate_hps(my_name)
            end
            
            -- Add group members
            for i = 1, group_count do
                local ok, member_tlo = pcall(function() return mq.TLO.Group.Member(i) end)
                if ok and member_tlo then
                    local name, class, level, current_hp, max_hp, zone
                    
                    pcall(function()
                        name = member_tlo.Name and member_tlo.Name() or member_tlo.CleanName and member_tlo.CleanName()
                        class = member_tlo.Class and member_tlo.Class()
                        level = tonumber(member_tlo.Level and member_tlo.Level() or 0)
                        current_hp = tonumber(member_tlo.CurrentHPs and member_tlo.CurrentHPs() or 0)
                        max_hp = tonumber(member_tlo.MaxHPs and member_tlo.MaxHPs() or 0)
                        zone = member_tlo.Zone and member_tlo.Zone()
                    end)
                    
                    if name and name ~= '' then
                        if not raid_data.members[name] then
                            raid_data.members[name] = create_member_data(name)
                        end
                        
                        local member = raid_data.members[name]
                        member.online = true
                        member.class = class or member.class
                        member.level = level or member.level
                        member.group_number = 1 -- All group members are in "group 1"
                        member.raid_position_group = 1  -- All group members in "group 1" for group mode
                        member.raid_position = i + 1  -- Position after self (self = 1, group members = 2+)
                        member.current_hp = current_hp or member.current_hp
                        member.max_hp = max_hp or member.max_hp
                        member.zone = zone or member.zone
                        member.last_seen = now
                        member.is_self = (name == my_name)
                        
                        if member.max_hp > 0 then
                            member.hp_percent = math.floor((member.current_hp / member.max_hp) * 100)
                        else
                            member.hp_percent = 100
                        end
                        
                        member.hps = calculate_hps(name)
                    end
                end
            end
        end
    end
    
    -- Clean up old offline members (remove after 5 minutes)
    local cutoff_time = now - 300
    for name, member in pairs(raid_data.members) do
        if not member.online and member.last_seen < cutoff_time then
            raid_data.members[name] = nil
        end
    end
end

-- Sorting functions
local function get_sorted_members()
    local members = {}
    
    -- Collect members to display
    for name, member in pairs(raid_data.members) do
        if config.display.show_offline or member.online then
            table.insert(members, member)
        end
    end
    
    -- Sort based on current mode
    if config.display.sort_mode == "alphabetical" then
        table.sort(members, function(a, b)
            return (a.name or ""):lower() < (b.name or ""):lower()
        end)
    elseif config.display.sort_mode == "raid_group" then
        table.sort(members, function(a, b)
            if a.raid_position_group ~= b.raid_position_group then
                return a.raid_position_group < b.raid_position_group
            end
            -- Within the same group, sort by raid position
            if a.raid_position ~= b.raid_position then
                return a.raid_position < b.raid_position
            end
            return (a.name or ""):lower() < (b.name or ""):lower()
        end)
    elseif config.display.sort_mode == "class" then
        table.sort(members, function(a, b)
            if a.class ~= b.class then
                return (a.class or ""):lower() < (b.class or ""):lower()
            end
            return (a.name or ""):lower() < (b.name or ""):lower()
        end)
    end
    
    return members
end

-- Config file management
local function get_script_dir()
    local info = debug.getinfo(1, 'S')
    local src = info and info.source or ''
    if src:sub(1,1) == '@' then src = src:sub(2) end
    local dir = src:match('^(.*[\\\\/])')
    return dir or ''
end

local CONFIG_PATH = config_paths.get_path('raid_hud_config.json')
local LEGACY_CONFIG_PATH = get_script_dir() .. 'raid_hud_config.json'

local function deep_merge(dst, src)
    if type(dst) ~= 'table' or type(src) ~= 'table' then return dst end
    for k, v in pairs(src) do
        if type(v) == 'table' then
            dst[k] = dst[k] or {}
            deep_merge(dst[k], v)
        else
            dst[k] = v
        end
    end
    return dst
end

local function save_config()
    if not has_json then return false end
    local encoded = json.encode(config, {indent = true})
    local f = io.open(CONFIG_PATH, 'w')
    if not f then return false end
    local ok = pcall(f.write, f, encoded)
    pcall(f.close, f)
    return ok and true or false
end

local function load_config()
    local f = io.open(CONFIG_PATH, 'r')
    local loaded_from_legacy = false
    if not f then
        f = io.open(LEGACY_CONFIG_PATH, 'r')
        if not f then return false end
        loaded_from_legacy = true
    end
    local ok, content = pcall(f.read, f, '*a')
    pcall(f.close, f)
    if not ok or not content or content == '' then return false end
    if not has_json then return false end
    local decoded, pos, err = json.decode(content)
    if not decoded or err then return false end
    deep_merge(config, decoded)
    if loaded_from_legacy then pcall(save_config) end
    return true
end

-- Try loading config on module load
pcall(load_config)

-- Styling
local function push_styles()
    -- Window background and styling
    if config.window.use_custom_bg then
        local bg = config.window.bg
        local alpha = (config.window.opacity or 0.9) * (bg.a or 1.0)
        ImGui.PushStyleColor(ImGuiCol.WindowBg, bg.r or 0.05, bg.g or 0.05, bg.b or 0.05, alpha)
        local border = config.window.border
        ImGui.PushStyleColor(ImGuiCol.Border, border.r or 0.3, border.g or 0.3, border.b or 0.3, border.a or 0.8)
    end
    
    -- Window padding and rounding
    ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, config.window.padding or 8, config.window.padding or 8)
    ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, config.window.rounding or 8)
    ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 4)
    ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, 3, 1)
end

local function pop_styles()
    ImGui.PopStyleVar(4)
    if config.window.use_custom_bg then 
        ImGui.PopStyleColor(2) 
    end
end

-- Settings window
local function draw_settings_window()
    if not state.showSettings then return end
    
    ImGui.SetNextWindowSize(500, 600, ImGuiCond.FirstUseEver)
    push_styles()
    
    local isOpen, shouldDraw = ImGui.Begin('Raid HUD Settings', true, ImGuiWindowFlags.None)
    if not isOpen then
        state.showSettings = false
        ImGui.End()
        pop_styles()
        return
    end
    
    if not shouldDraw then 
        ImGui.End() 
        pop_styles() 
        return 
    end
    
    if ImGui.CollapsingHeader('Display Settings', ImGuiTreeNodeFlags.DefaultOpen) then
        -- Sort mode with buttons like the original header
        ImGui.Text('Sort Mode:')
        ImGui.SameLine()
        
        local sort_modes = {
            {key = "alphabetical", label = "ABC"},
            {key = "raid_group", label = "GRP"},
            {key = "class", label = "CLS"}
        }
        
        for i, mode in ipairs(sort_modes) do
            if i > 1 then ImGui.SameLine() end
            
            local is_active = (config.display.sort_mode == mode.key)
            if is_active then
                ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.6, 0.2, 0.8)
            end
            
            if ImGui.SmallButton(mode.label .. '##sort') then
                config.display.sort_mode = mode.key
            end
            
            if is_active then
                ImGui.PopStyleColor()
            end
        end
        
        ImGui.Spacing()
        
        -- Name/Class toggle buttons
        ImGui.Text('Display Names As:')
        ImGui.SameLine()
        
        local name_active = not config.display.show_class_names and not config.display.show_name_with_class
        if name_active then
            ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.6, 0.2, 0.8)
        end
        
        if ImGui.SmallButton('NAME##display') then
            config.display.show_class_names = false
            config.display.show_name_with_class = false
        end
        
        if name_active then
            ImGui.PopStyleColor()
        end
        
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Show only character names')
        end
        
        ImGui.SameLine()
        
        local class_active = config.display.show_class_names
        if class_active then
            ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.6, 0.2, 0.8)
        end
        
        if ImGui.SmallButton('CLASS##display') then
            config.display.show_class_names = not config.display.show_class_names
            -- Ensure only one option is active at a time
            if config.display.show_class_names then
                config.display.show_name_with_class = false
            end
        end
        
        if class_active then
            ImGui.PopStyleColor()
        end
        
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Show only class abbreviations')
        end
        
        ImGui.SameLine()
        
        local name_class_active = config.display.show_name_with_class
        if name_class_active then
            ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.6, 0.2, 0.8)
        end
        
        if ImGui.SmallButton('NAME (CLASS)##display') then
            config.display.show_name_with_class = not config.display.show_name_with_class
            -- Ensure only one option is active at a time
            if config.display.show_name_with_class then
                config.display.show_class_names = false
            end
        end
        
        if name_class_active then
            ImGui.PopStyleColor()
        end
        
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Show both name and class in "Name (Class)" format')
        end
        
        
        ImGui.Spacing()
        
        -- Other display options
        
        local show_mana, mana_changed = ImGui.Checkbox('Show Mana Column', config.display.show_mana)
        if mana_changed then
            config.display.show_mana = show_mana
        end
        
        local show_distance, distance_changed = ImGui.Checkbox('Show Distance Column', config.display.show_distance)
        if distance_changed then
            config.display.show_distance = show_distance
        end
        
        local show_offline, offline_changed = ImGui.Checkbox('Show Offline Members', config.display.show_offline)
        if offline_changed then
            config.display.show_offline = show_offline
        end
        
        local compact, compact_changed = ImGui.Checkbox('Compact Mode', config.display.compact_mode)
        if compact_changed then
            config.display.compact_mode = compact
        end
        
        ImGui.Spacing()
        ImGui.Separator()
        ImGui.Text('Group Layout Settings')
        
        local group_layout, layout_changed = ImGui.Checkbox('Enable Multi-Column Layout', config.display.enable_group_layout)
        if layout_changed then
            config.display.enable_group_layout = group_layout
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Display raid members in multiple columns (6 members per column)')
        end
        
        -- Only show groups per row slider if group layout is enabled
        if config.display.enable_group_layout then
            local groups_per_row, groups_changed = ImGui.SliderInt('Columns per Row', config.display.groups_per_row, 2, 6)
            if groups_changed then
                config.display.groups_per_row = groups_per_row
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Number of member columns to display horizontally (2-6)')
            end
            
            local group_spacing, spacing_changed = ImGui.SliderInt('Group Spacing', config.display.group_spacing, 5, 30)
            if spacing_changed then
                config.display.group_spacing = group_spacing
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Extra horizontal spacing between group columns')
            end
            
            ImGui.Spacing()
            ImGui.Text('Grouping Method:')
            ImGui.SameLine()
            
            local grouping_methods = {
                {key = "auto", label = "AUTO", tooltip = "Use EQ group numbers if available, otherwise position-based"},
                {key = "position", label = "POS", tooltip = "Position-based: 1-6=Group1, 7-12=Group2, etc."},
                {key = "eq_groups", label = "EQ", tooltip = "Use EverQuest's actual group numbers only"}
            }
            
            for i, method in ipairs(grouping_methods) do
                if i > 1 then ImGui.SameLine() end
                
                local is_active = (config.display.grouping_method == method.key)
                if is_active then
                    ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.6, 0.2, 0.8)
                end
                
                if ImGui.SmallButton(method.label .. '##grouping') then
                    config.display.grouping_method = method.key
                end
                
                if is_active then
                    ImGui.PopStyleColor()
                end
                
                if ImGui.IsItemHovered() then
                    ImGui.SetTooltip(method.tooltip)
                end
            end
        else
            ImGui.TextColored(0.6, 0.6, 0.6, 1.0, 'Group layout disabled - displays groups vertically')
        end
        
        ImGui.Spacing()
        ImGui.Separator()
        ImGui.Text('Separate Group Windows')
        
        local separate_windows, separate_changed = ImGui.Checkbox('Enable Separate Group Windows', config.display.separate_group_windows)
        if separate_changed then
            config.display.separate_group_windows = separate_windows
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Show each raid group in its own separate window (only works with raid_group sort mode)')
        end
        
        -- Only show separate window settings if enabled
        if config.display.separate_group_windows then
            local max_groups, groups_changed = ImGui.SliderInt('Max Groups to Show', config.display.max_groups_to_show, 1, 12)
            if groups_changed then
                config.display.max_groups_to_show = max_groups
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Maximum number of group windows to display (1-12)')
            end
            
            local window_spacing, spacing_changed = ImGui.SliderInt('Window Spacing', config.display.group_window_spacing, 5, 50)
            if spacing_changed then
                config.display.group_window_spacing = window_spacing
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Vertical spacing multiplier between group windows')
            end
            
            -- Show note about sort mode requirement
            if config.display.sort_mode ~= "raid_group" then
                ImGui.TextColored(1.0, 0.6, 0.0, 1.0, 'Note: Requires "Raid Group" sort mode to work')
            end
        else
            ImGui.TextColored(0.6, 0.6, 0.6, 1.0, 'Separate windows disabled - uses single window')
        end
        
        ImGui.Spacing()
        ImGui.Separator()
        ImGui.Text('Toggle Button Settings')
        
        local toggle_enabled, toggle_enabled_changed = ImGui.Checkbox('Show Toggle Button', config.toggle_button.enabled)
        if toggle_enabled_changed then
            config.toggle_button.enabled = toggle_enabled
            state.showToggleButton = toggle_enabled
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Show a floating button to toggle the raid HUD on/off')
        end
        
        -- Only show toggle button settings if enabled
        if config.toggle_button.enabled then
            local button_size, size_changed = ImGui.SliderInt('Button Size', config.toggle_button.size, 20, 80)
            if size_changed then
                config.toggle_button.size = button_size
            end
            
            local button_opacity, opacity_changed = ImGui.SliderFloat('Button Opacity', config.toggle_button.opacity, 0.3, 1.0)
            if opacity_changed then
                config.toggle_button.opacity = button_opacity
            end
            
            local button_text = tostring(config.toggle_button.text or "RAID")
            local new_text, text_changed = ImGui.InputTextWithHint('Button Text', 'RAID', button_text, 32)
            if text_changed then
                config.toggle_button.text = new_text
            end
            
            local lock_position, lock_changed = ImGui.Checkbox('Lock Button Position', config.toggle_button.lock_position)
            if lock_changed then
                config.toggle_button.lock_position = lock_position
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Prevent the button from being dragged to a new position')
            end
            
            if ImGui.Button('Reset Button Position') then
                config.toggle_button.pos_x = 50
                config.toggle_button.pos_y = 50
            end
            if ImGui.IsItemHovered() then
                ImGui.SetTooltip('Move the toggle button back to the default position')
            end
        else
            ImGui.TextColored(0.6, 0.6, 0.6, 1.0, 'Toggle button disabled')
        end
        
        ImGui.Spacing()
        
        -- Auto-size toggle button
        ImGui.Text('Window Sizing:')
        ImGui.SameLine()
        
        local auto_size_active = config.display.auto_size
        if auto_size_active then
            ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.6, 0.2, 0.8)
        end
        
        if ImGui.SmallButton('AUTO') then
            config.display.auto_size = not config.display.auto_size
        end
        
        if auto_size_active then
            ImGui.PopStyleColor()
        end
        
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip(config.display.auto_size and 'Auto-sizing enabled (window resizes to fit content)' or 'Auto-sizing disabled (manual window height)')
        end
        
        ImGui.SameLine()
        ImGui.Text(config.display.auto_size and '(Auto-sizing ON)' or '(Manual sizing)')
        
        -- Also keep the checkbox for clarity
        local auto_size, auto_size_changed = ImGui.Checkbox('Auto-size Window', config.display.auto_size)
        if auto_size_changed then
            config.display.auto_size = auto_size
        end
        
        -- Refresh rate
        local refresh_rate, refresh_changed = ImGui.SliderFloat('Refresh Rate (sec)', config.display.refresh_rate, 0.5, 5.0)
        if refresh_changed then
            config.display.refresh_rate = refresh_rate
        end
        
        -- HPS window
        local hps_window, hps_window_changed = ImGui.SliderFloat('HPS Window (sec)', config.display.hps_window, 5.0, 60.0)
        if hps_window_changed then
            config.display.hps_window = hps_window
        end
    end
    
    if ImGui.CollapsingHeader('Window Settings') then
        local opacity, opacity_changed = ImGui.SliderFloat('Opacity', config.window.opacity, 0.3, 1.0)
        if opacity_changed then
            config.window.opacity = opacity
        end
        
        local width, width_changed = ImGui.SliderInt('Width', config.window.width, 200, 600)
        if width_changed then
            config.window.width = width
        end
        
        local hide_title, title_changed = ImGui.Checkbox('Hide Title Bar', config.window.hide_title_bar)
        if title_changed then
            config.window.hide_title_bar = hide_title
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Hide the window title bar for a cleaner look')
        end
        
        -- Only show manual height control if auto-sizing is disabled
        if not config.display.auto_size then
            local height, height_changed = ImGui.SliderInt('Height', config.window.height, 200, 800)
            if height_changed then
                config.window.height = height
            end
        else
            ImGui.TextColored(0.7, 0.7, 0.7, 1.0, 'Height: Auto-sized')
        end
        
        ImGui.Separator()
        ImGui.Text('Auto-sizing Settings')
        
        -- Auto-sizing bounds
        local min_height, min_changed = ImGui.SliderInt('Min Height', config.display.min_window_height, 80, 400)
        if min_changed then
            config.display.min_window_height = min_height
        end
        
        local max_height, max_changed = ImGui.SliderInt('Max Height', config.display.max_window_height, 200, 1200)
        if max_changed then
            config.display.max_window_height = max_height
        end
        
        local line_spacing, spacing_changed = ImGui.SliderInt('Line Spacing', config.display.line_spacing, 0, 10)
        if spacing_changed then
            config.display.line_spacing = line_spacing
        end
        if ImGui.IsItemHovered() then
            ImGui.SetTooltip('Extra spacing between member lines')
        end
        
        ImGui.Separator()
        ImGui.Text('Column Width Settings')
        
        local name_width, name_width_changed = ImGui.SliderInt('Name Width', config.display.name_width, 80, 200)
        if name_width_changed then
            config.display.name_width = name_width
        end
        
        local class_width, class_width_changed = ImGui.SliderInt('Class Width', config.display.class_width, 30, 100)
        if class_width_changed then
            config.display.class_width = class_width
        end
        
        local name_class_width, name_class_width_changed = ImGui.SliderInt('Name (Class) Width', config.display.name_class_width, 100, 300)
        if name_class_width_changed then
            config.display.name_class_width = name_class_width
        end
        
        local mana_width, mana_width_changed = ImGui.SliderInt('Mana Width', config.display.mana_width, 40, 100)
        if mana_width_changed then
            config.display.mana_width = mana_width
        end
        
        local distance_width, distance_width_changed = ImGui.SliderInt('Distance Width', config.display.distance_width, 50, 120)
        if distance_width_changed then
            config.display.distance_width = distance_width
        end
    end
    
    ImGui.Separator()
    if ImGui.Button('Save Settings') then
        save_config()
    end
    ImGui.SameLine()
    if ImGui.Button('Reset to Defaults') then
        -- Reset config to defaults (would need to redefine defaults)
    end
    
    ImGui.End()
    pop_styles()
end

-- Draw floating toggle button matching EmuBot style
local function draw_toggle_button()
    if not state.showToggleButton or not config.toggle_button.enabled then return end
    
    -- Set button position
    ImGui.SetNextWindowPos(config.toggle_button.pos_x, config.toggle_button.pos_y, ImGuiCond.FirstUseEver)
    
    -- Set button size (match EmuBot default)
    local button_size = config.toggle_button.size or 50
    ImGui.SetNextWindowSize(button_size + 8, button_size + 8, ImGuiCond.FirstUseEver)
    
    -- Configure window flags for floating button
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
    
    -- Add no move flag if position is locked
    if config.toggle_button.lock_position then
        flags = bit32.bor(flags, ImGuiWindowFlags.NoMove)
    end
    
    -- Apply EmuBot floating button styling
    ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, 4, 4)
    ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 8)
    ImGui.PushStyleVar(ImGuiStyleVar.WindowBorderSize, 1)
    
    -- Apply window background and border colors (EmuBot style)
    ImGui.PushStyleColor(ImGuiCol.WindowBg, 0.1, 0.1, 0.1, 0.85)
    ImGui.PushStyleColor(ImGuiCol.Border, 0.4, 0.4, 0.4, 0.8)
    
    local isOpen, shouldDraw = ImGui.Begin('##RaidHUDToggle', state.showToggleButton, flags)
    
    if not isOpen then
        state.showToggleButton = false
        ImGui.End()
        ImGui.PopStyleColor(2)
        ImGui.PopStyleVar(3)
        return
    end
    
    if not shouldDraw then
        ImGui.End()
        ImGui.PopStyleColor(2)
        ImGui.PopStyleVar(3)
        return
    end
    
    -- Track position as it moves (EmuBot style)
    if not config.toggle_button.lock_position then
        local pos_x, pos_y = ImGui.GetWindowPos()
        config.toggle_button.pos_x = pos_x
        config.toggle_button.pos_y = pos_y
    end
    
    -- Choose colors based on current raid HUD state (EmuBot style)
    if state.show then
        -- Open state: orange-ish (like EmuBot when open)
        ImGui.PushStyleColor(ImGuiCol.Button, 0.85, 0.55, 0.15, 0.95)
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.95, 0.65, 0.25, 1.0)
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.75, 0.45, 0.10, 1.0)
    else
        -- Closed state: green (like EmuBot when closed)
        ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.6, 0.2, 0.9)
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.25, 0.7, 0.25, 1.0)
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.15, 0.5, 0.15, 1.0)
    end
    
    -- Rounded button corners (EmuBot style)
    ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, math.min(12, button_size * 0.4))
    
    -- Create the toggle button (rectangular like EmuBot, not circular)
    local button_text = config.toggle_button.text or "R"
    local clicked = ImGui.Button(button_text, button_size, button_size)
    
    -- Pop button style (frame rounding)
    ImGui.PopStyleVar(1)
    -- Pop button colors  
    ImGui.PopStyleColor(3)
    
    -- Handle button click
    if clicked then
        M.toggle()
    end
    
    -- Handle right-click to open settings (like EmuBot does)
    if ImGui.IsItemClicked(ImGuiMouseButton.Right) then
        state.showSettings = true
    end
    
    -- Simple tooltip (EmuBot style)
    if ImGui.IsItemHovered() then
        local status = state.show and "Open" or "Closed"
        ImGui.SetTooltip(string.format("Toggle Raid HUD (%s) | Right-click: Settings", status))
    end
    
    ImGui.End()
    
    -- Pop window styling (applied at the beginning)
    ImGui.PopStyleColor(2)  -- Window background and border
    ImGui.PopStyleVar(3)    -- Window padding, rounding, and border size
end

-- Draw a single group window
local function draw_group_window(group_number, members)
    local window_name = string.format("Raid Group %d", group_number)
    
    -- Calculate window position (stack windows vertically with better spacing)
    local base_pos_x = 100
    local spacing_multiplier = math.max(5, config.display.group_window_spacing or 20)
    local base_pos_y = 100 + (group_number - 1) * spacing_multiplier * 8
    
    ImGui.SetNextWindowPos(base_pos_x, base_pos_y, ImGuiCond.FirstUseEver)
    
    -- Set window size behavior
    if config.display.auto_size then
        -- Use ImGui's natural auto-resize but constrain both width and height
        ImGui.SetNextWindowSizeConstraints(
            ImVec2(200, config.display.min_window_height or 120),
            ImVec2(config.window.width, config.display.max_window_height or 800)
        )
        -- Let ImGui auto-size naturally but provide a width hint
        ImGui.SetNextWindowSize(config.window.width, -1, ImGuiCond.FirstUseEver)
    else
        -- Manual sizing - use configured dimensions but adjust height for fewer members
        local estimated_height = math.min(config.window.height, 80 + #members * 25)
        ImGui.SetNextWindowSize(config.window.width, estimated_height, ImGuiCond.FirstUseEver)
    end
    
    push_styles()
    
    -- Configure window flags based on settings
    local flags = bit32.bor(
        ImGuiWindowFlags.AlwaysAutoResize,
        ImGuiWindowFlags.NoScrollbar,
        ImGuiWindowFlags.NoScrollWithMouse
    )
    
    -- Add title bar hiding if enabled
    if config.window.hide_title_bar then
        flags = bit32.bor(flags, ImGuiWindowFlags.NoTitleBar)
    end
    
    local isOpen, shouldDraw = ImGui.Begin(window_name, true, flags)
    
    if not isOpen then
        ImGui.End()
        pop_styles()
        return false -- Signal that this window was closed
    end
    
    if not shouldDraw then
        ImGui.End()
        pop_styles()
        return true -- Keep window open but don't draw
    end
    
    -- Right-click detection for settings anywhere in window
    if ImGui.IsWindowHovered() and ImGui.IsMouseClicked(ImGuiMouseButton.Right) then
        state.showSettings = not state.showSettings
    end
    
    -- Show group header and member count
    if config.window.hide_title_bar then
        -- Make header more prominent when title bar is hidden
        ImGui.PushStyleColor(ImGuiCol.Text, config.colors.header.r, config.colors.header.g, config.colors.header.b, config.colors.header.a)
        ImGui.Text(string.format("Group %d (%d members)", group_number, #members))
        ImGui.PopStyleColor()
    else
        -- Normal header when title bar is visible
        ImGui.TextColored(config.colors.header.r, config.colors.header.g, config.colors.header.b, config.colors.header.a, 
                         string.format("Group %d (%d members)", group_number, #members))
    end
    
    if ImGui.IsItemHovered() then
        ImGui.SetTooltip('Right-click anywhere in window for settings')
    end
    
    ImGui.Separator()
    
    -- Member display - use standard single-column layout
    if #members == 0 then
        ImGui.Text("No members in this group")
    else
        local columns = 2  -- Name and HP% are always shown
        if config.display.show_mana then columns = columns + 1 end
        if config.display.show_distance then columns = columns + 1 end
        local table_flags = bit32.bor(ImGuiTableFlags.Resizable, ImGuiTableFlags.BordersV)
        
        -- Apply line spacing if configured, otherwise use compact padding
        if config.display.line_spacing > 0 then
            ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, 3, config.display.line_spacing)
        else
            ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, 3, 1)
        end
        
        if ImGui.BeginTable('GroupMembers' .. group_number, columns, table_flags) then
            -- Setup columns in order: First column (Name/Class/Name(Class)), HP%, Mana%, Distance
            local first_label, first_width
            if config.display.show_name_with_class then
                first_label = 'Name (Class)'
                first_width = config.display.name_class_width or 160
            elseif config.display.show_class_names then
                first_label = 'Class'
                first_width = config.display.class_width or 50
            else
                first_label = 'Name'
                first_width = config.display.name_width or 120
            end
            ImGui.TableSetupColumn(first_label, ImGuiTableColumnFlags.WidthFixed, first_width)
            ImGui.TableSetupColumn('HP%', ImGuiTableColumnFlags.WidthFixed, 60)
            if config.display.show_mana then
                ImGui.TableSetupColumn('Mana%', ImGuiTableColumnFlags.WidthFixed, config.display.mana_width or 60)
            end
            if config.display.show_distance then
                ImGui.TableSetupColumn('Distance', ImGuiTableColumnFlags.WidthFixed, config.display.distance_width or 70)
            end
            
            for _, member in ipairs(members) do
                render_member_row(member)
            end
            
            ImGui.EndTable()
        end
        
        -- Pop cell padding style
        ImGui.PopStyleVar(1)
    end
    
    ImGui.End()
    pop_styles()
    
    return true -- Window is still open
end

-- Draw separate group windows
local function draw_separate_group_windows(members)
    -- Ensure configuration is valid
    local max_groups = math.max(1, math.min(12, config.display.max_groups_to_show or 6))
    
    -- Create a position-indexed table of members
    local members_by_position = {}
    for _, member in ipairs(members) do
        if member.raid_position and member.raid_position > 0 then
            members_by_position[member.raid_position] = member
        end
    end
    
    -- Group members by their position ranges (1-6 = group 1, 7-12 = group 2, etc.)
    local groups = {}
    for pos = 1, max_groups * 6 do
        local group_number = math.ceil(pos / 6)
        if group_number <= max_groups then
            if not groups[group_number] then
                groups[group_number] = {}
            end
            local member = members_by_position[pos]
            if member then
                table.insert(groups[group_number], member)
            end
        end
    end
    
    -- Draw each group that has members, or show empty groups optionally
    for group_num = 1, max_groups do
        local group_members = groups[group_num] or {}
        -- Only draw windows for groups with members, unless user wants to see empty groups
        if #group_members > 0 then
            draw_group_window(group_num, group_members)
        end
    end
end

-- Main HUD window
local function draw_raid_hud()
    if not state.show then return end
    
    -- Update data
    update_raid_data()
    
    -- Get sorted members
    local members = get_sorted_members()
    
    -- Check if we should use separate group windows mode
    if config.display.separate_group_windows and config.display.sort_mode == "raid_group" then
        draw_separate_group_windows(members)
        return
    end
    
    -- Auto-sizing setup - let ImGui handle the sizing naturally
    
    -- Set window size behavior
    if config.display.auto_size then
        -- Use ImGui's natural auto-resize but constrain both width and height
        ImGui.SetNextWindowSizeConstraints(
            ImVec2(200, config.display.min_window_height or 120),
            ImVec2(config.window.width, config.display.max_window_height or 800)
        )
        -- Let ImGui auto-size naturally but provide a width hint
        ImGui.SetNextWindowSize(config.window.width, -1, ImGuiCond.FirstUseEver)
    else
        -- Manual sizing - use configured dimensions
        ImGui.SetNextWindowSize(config.window.width, config.window.height, ImGuiCond.FirstUseEver)
    end
    
    push_styles()
    
    -- Configure window flags based on settings
    local flags = bit32.bor(
        ImGuiWindowFlags.AlwaysAutoResize,
        ImGuiWindowFlags.NoScrollbar,
        ImGuiWindowFlags.NoScrollWithMouse
    )
    
    -- Add title bar hiding if enabled
    if config.window.hide_title_bar then
        flags = bit32.bor(flags, ImGuiWindowFlags.NoTitleBar)
    end
    
    local isOpen, shouldDraw = ImGui.Begin('Raid HUD', state.show, flags)
    
    if not isOpen then
        state.show = false
        ImGui.End()
        pop_styles()
        return
    end
    
    if not shouldDraw then
        ImGui.End()
        pop_styles()
        return
    end
    
    -- Right-click detection for settings anywhere in window
    if ImGui.IsWindowHovered() and ImGui.IsMouseClicked(ImGuiMouseButton.Right) then
        state.showSettings = not state.showSettings
    end
    
    -- Show member count and sort info (more prominent if title bar is hidden)
    local sort_label = config.display.sort_mode:gsub("_", " "):gsub("(%w)(%w*)", function(first, rest) 
        return first:upper() .. rest:lower() 
    end)
    
    if config.window.hide_title_bar then
        -- Make header more prominent when title bar is hidden
        ImGui.PushStyleColor(ImGuiCol.Text, config.colors.header.r, config.colors.header.g, config.colors.header.b, config.colors.header.a)
        ImGui.Text(string.format("Raid HUD - %s (%d members)", sort_label, #members))
        ImGui.PopStyleColor()
    else
        -- Normal header when title bar is visible
        ImGui.TextColored(config.colors.header.r, config.colors.header.g, config.colors.header.b, config.colors.header.a, 
                         string.format("%s (%d members)", sort_label, #members))
    end
    
    if ImGui.IsItemHovered() then
        ImGui.SetTooltip('Right-click anywhere in window for settings')
    end
    
    ImGui.Separator()
    
    -- Member display
    if #members == 0 then
        ImGui.Text("No raid/group members found")
    else
        -- Check if we should use multi-column layout
        if config.display.sort_mode == "raid_group" and config.display.enable_group_layout then
            -- Multi-column position-based layout (1-6, 7-12, 13-18, etc.)
            local columns_per_row = config.display.groups_per_row
            local max_members_per_column = 6
            
            -- Apply line spacing if configured, otherwise use compact padding
            if config.display.line_spacing > 0 then
                ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, 3, config.display.line_spacing)
            else
                ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, 3, 1)
            end
            
            -- Calculate member data columns
            local member_columns = 2  -- Name and HP% are always shown
            if config.display.show_mana then member_columns = member_columns + 1 end
            if config.display.show_distance then member_columns = member_columns + 1 end
            
            -- Create a position-indexed table of members
            local members_by_position = {}
            for _, member in ipairs(members) do
                if member.raid_position and member.raid_position > 0 then
                    members_by_position[member.raid_position] = member
                end
            end
            
            -- Find the highest raid position to determine how many columns we need
            local max_position = 0
            for pos, _ in pairs(members_by_position) do
                if pos > max_position then max_position = pos end
            end
            
            -- Calculate how many columns we actually need overall (across all rows)
            local total_columns_needed = math.ceil(max_position / max_members_per_column)
            if total_columns_needed == 0 then total_columns_needed = 1 end
            
            local table_flags = bit32.bor(ImGuiTableFlags.Resizable, ImGuiTableFlags.BordersV, ImGuiTableFlags.BordersOuterH, ImGuiTableFlags.SizingFixedFit)
            
            -- Render rows of columns (each row shows up to columns_per_row columns)
            local row_count = math.ceil(total_columns_needed / columns_per_row)
            for row_idx = 1, row_count do
                local first_column_index = (row_idx - 1) * columns_per_row + 1
                local columns_in_row = math.min(columns_per_row, total_columns_needed - (first_column_index - 1))
                local total_columns = columns_in_row * member_columns
                if ImGui.BeginTable('RaidMembersMultiColumnRow' .. row_idx, total_columns, table_flags) then
                    -- Setup columns for each position column
                    local first_col_width, first_base_label
                    if config.display.show_name_with_class then
                        first_base_label = 'Name (Class)'
                        first_col_width = config.display.name_class_width or 160
                    elseif config.display.show_class_names then
                        first_base_label = 'Class'
                        first_col_width = config.display.class_width or 50
                    else
                        first_base_label = 'Name'
                        first_col_width = config.display.name_width or 120
                    end
                    
                    for col = 1, columns_in_row do
                    local first_label = first_base_label .. tostring(col)
                    ImGui.TableSetupColumn(first_label, ImGuiTableColumnFlags.WidthFixed, first_col_width)
                    ImGui.TableSetupColumn('HP%' .. col, ImGuiTableColumnFlags.WidthFixed, 60)
                    if config.display.show_mana then
                        ImGui.TableSetupColumn('Mana%' .. col, ImGuiTableColumnFlags.WidthFixed, config.display.mana_width or 60)
                    end
                    if config.display.show_distance then
                        ImGui.TableSetupColumn('Distance' .. col, ImGuiTableColumnFlags.WidthFixed, config.display.distance_width or 70)
                    end
                end
                
                -- Render column headers for this row
                ImGui.TableNextRow()
                for col = 1, columns_in_row do
                    local column_number = first_column_index + (col - 1)
                    local group_number = column_number
                    
                    -- Column header
                    ImGui.TableNextColumn()
                    ImGui.TextColored(config.colors.header.r, config.colors.header.g, config.colors.header.b, config.colors.header.a,
                                    string.format("Group %d", group_number))
                    
                    -- Skip remaining member columns for this header
                    for i = 2, member_columns do
                        ImGui.TableNextColumn()
                        ImGui.Text("")
                    end
                end
                
                -- Render member rows (up to max_members_per_column rows)
                for row = 1, max_members_per_column do
                    ImGui.TableNextRow()
                    for col = 1, columns_in_row do
                        local column_number = first_column_index + (col - 1)
                        local raid_position = (column_number - 1) * max_members_per_column + row
                        local member = members_by_position[raid_position]
                        
                        if member then
                            render_member_cells_inline(member)
                        else
                            -- Empty member slot - fill with blank cells
                            for i = 1, member_columns do
                                ImGui.TableNextColumn()
                                ImGui.Text("")
                            end
                        end
                    end
                end
                
                ImGui.EndTable()
                
                -- Spacing between rows of columns
                if row_idx < row_count then
                    ImGui.Spacing()
                end
                end
            end
            
            -- Pop cell padding style
            ImGui.PopStyleVar(1)
        else
            -- Standard single-column layout (existing logic)
            local columns = 2  -- Name and HP% are always shown
            if config.display.show_mana then columns = columns + 1 end
            if config.display.show_distance then columns = columns + 1 end
            local table_flags = bit32.bor(ImGuiTableFlags.Resizable, ImGuiTableFlags.BordersV)
            
            -- Apply line spacing if configured, otherwise use compact padding
            if config.display.line_spacing > 0 then
                ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, 3, config.display.line_spacing)
            else
                ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, 3, 1)
            end
            
            if ImGui.BeginTable('RaidMembers', columns, table_flags) then
                -- Setup columns in order: First column (Name/Class/Name(Class)), HP%, Mana%, Distance
                local first_label, first_width
                if config.display.show_name_with_class then
                    first_label = 'Name (Class)'
                    first_width = config.display.name_class_width or 160
                elseif config.display.show_class_names then
                    first_label = 'Class'
                    first_width = config.display.class_width or 50
                else
                    first_label = 'Name'
                    first_width = config.display.name_width or 120
                end
                ImGui.TableSetupColumn(first_label, ImGuiTableColumnFlags.WidthFixed, first_width)
                ImGui.TableSetupColumn('HP%', ImGuiTableColumnFlags.WidthFixed, 60)
                if config.display.show_mana then
                    ImGui.TableSetupColumn('Mana%', ImGuiTableColumnFlags.WidthFixed, config.display.mana_width)
                end
                if config.display.show_distance then
                    ImGui.TableSetupColumn('Distance', ImGuiTableColumnFlags.WidthFixed, config.display.distance_width)
                end
                
                -- Group headers for raid_group mode (single column layout)
                local current_group = -1
                
                for _, member in ipairs(members) do
                    -- Show group header if in raid group mode (using raid position groups)
                    local member_group = member.raid_position_group or 1
                    if config.display.sort_mode == "raid_group" and member_group ~= current_group then
                        current_group = member_group
                        ImGui.TableNextRow()
                        ImGui.TableNextColumn()
                        ImGui.TextColored(config.colors.header.r, config.colors.header.g, config.colors.header.b, config.colors.header.a,
                                        string.format("Group %d", current_group))
                        -- Skip remaining columns for group header
                        for i = 2, columns do
                            ImGui.TableNextColumn()
                            ImGui.Text("")
                        end
                    end
                    
                    render_member_row(member)
                end
                
                ImGui.EndTable()
            end
            
            -- Pop cell padding style (always applied now)
            ImGui.PopStyleVar(1)
        end
    end
    
    ImGui.End()
    pop_styles()
end

-- Event system for heal tracking
local heal_events_registered = false

local function register_heal_events()
    if heal_events_registered then return end
    
    -- Register heal events - these are basic patterns, you may need to adjust for your server
    mq.event("RaidHealEvent", "#1# healed #2# for #3# points of damage", function(line, healer, target, amount)
        local heal_amount = tonumber(amount) or 0
        if heal_amount > 0 then
            add_heal_event(healer, target, heal_amount)
        end
    end)
    
    -- Additional heal patterns
    mq.event("RaidHealSelfEvent", "You heal #1# for #2# points of damage", function(line, target, amount)
        local my_name = mq.TLO.Me and mq.TLO.Me.CleanName and mq.TLO.Me.CleanName() or "You"
        local heal_amount = tonumber(amount) or 0
        if heal_amount > 0 then
            add_heal_event(my_name, target, heal_amount)
        end
    end)
    
    heal_events_registered = true
end

local function unregister_heal_events()
    if not heal_events_registered then return end
    
    mq.unevent("RaidHealEvent")
    mq.unevent("RaidHealSelfEvent")
    heal_events_registered = false
end

-- Public API
function M.show()
    state.show = true
    register_heal_events()
end

function M.hide()
    state.show = false
    unregister_heal_events()
end

function M.toggle()
    if state.show then
        M.hide()
    else
        M.show()
    end
end

-- Register MQ bind: /ebraid show | hide | toggle | button
pcall(function()
    if mq and mq.bind then
        mq.bind('/ebraid', function(args)
            local sub = args or ''
            sub = sub:match('%S+') or ''
            sub = sub:lower()
            if sub == 'show' then
                M.show()
            elseif sub == 'hide' then
                M.hide()
            elseif sub == 'toggle' or sub == '' then
                M.toggle()
            elseif sub == 'button' then
                M.toggle_button_visibility()
            else
                if mq and mq.cmd then 
                    mq.cmd('/echo Usage: /ebraid [show|hide|toggle|button]')
                    mq.cmd('/echo   show   - Show the raid HUD')
                    mq.cmd('/echo   hide   - Hide the raid HUD')
                    mq.cmd('/echo   toggle - Toggle the raid HUD on/off')
                    mq.cmd('/echo   button - Toggle the floating button on/off')
                end
            end
        end)
    end
end)

function M.is_visible()
    return state.show
end

function M.set_sort_mode(mode)
    if mode == "alphabetical" or mode == "raid_group" or mode == "class" then
        config.display.sort_mode = mode
    end
end

function M.get_sort_mode()
    return config.display.sort_mode
end

function M.toggle_class_names()
    config.display.show_class_names = not config.display.show_class_names
    -- Ensure only one display mode is active
    if config.display.show_class_names then
        config.display.show_name_with_class = false
    end
end

function M.toggle_name_with_class()
    config.display.show_name_with_class = not config.display.show_name_with_class
    -- Ensure only one display mode is active
    if config.display.show_name_with_class then
        config.display.show_class_names = false
    end
end

function M.set_name_display_mode(mode)
    -- mode can be "name", "class", or "name_class"
    config.display.show_class_names = false
    config.display.show_name_with_class = false
    
    if mode == "class" then
        config.display.show_class_names = true
    elseif mode == "name_class" then
        config.display.show_name_with_class = true
    end
    -- Default "name" mode requires no flags to be set
end

function M.get_name_display_mode()
    if config.display.show_name_with_class then
        return "name_class"
    elseif config.display.show_class_names then
        return "class"
    else
        return "name"
    end
end

function M.toggle_auto_size()
    config.display.auto_size = not config.display.auto_size
end

function M.set_auto_size(enabled)
    config.display.auto_size = enabled and true or false
end

function M.is_auto_size_enabled()
    return config.display.auto_size
end

function M.toggle_title_bar()
    config.window.hide_title_bar = not config.window.hide_title_bar
end

function M.set_title_bar_hidden(hidden)
    config.window.hide_title_bar = hidden and true or false
end

function M.is_title_bar_hidden()
    return config.window.hide_title_bar
end

function M.clear_heal_data()
    raid_data.heal_events = {}
    raid_data.heal_index = 1
    for name, member in pairs(raid_data.members) do
        member.heal_timestamps = {}
        member.total_heals = 0
        member.hps = 0
    end
end

function M.get_member_count()
    local count = 0
    for name, member in pairs(raid_data.members) do
        if config.display.show_offline or member.online then
            count = count + 1
        end
    end
    return count
end

-- Toggle button API
function M.show_toggle_button()
    state.showToggleButton = true
    config.toggle_button.enabled = true
end

function M.hide_toggle_button()
    state.showToggleButton = false
end

function M.toggle_button_visibility()
    if state.showToggleButton then
        M.hide_toggle_button()
    else
        M.show_toggle_button()
    end
end

function M.is_toggle_button_visible()
    return state.showToggleButton and config.toggle_button.enabled
end

function M.set_toggle_button_enabled(enabled)
    config.toggle_button.enabled = enabled and true or false
    state.showToggleButton = config.toggle_button.enabled
end

function M.set_toggle_button_text(text)
    config.toggle_button.text = tostring(text or "RAID")
end

-- Main draw function to be called by the ImGui loop
function M.draw()
    draw_toggle_button()
    draw_raid_hud()
    draw_settings_window()
    
    -- Process MQ events for heal tracking
    if heal_events_registered then
        mq.doevents()
    end
end

-- Initialize
function M.init()
    load_config()
    -- Ensure toggle button state matches config
    state.showToggleButton = config.toggle_button.enabled
end

-- Cleanup
function M.cleanup()
    unregister_heal_events()
    save_config()
end

return M
