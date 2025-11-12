local mq = require('mq')
local config_paths = require('config')
local repo = require('ui.command_repo')

local has_json, json = pcall(require, 'dkjson')

local M = {}

local state = {
    auto_defend_enabled = nil, -- Updated via chat events
    _aad_query_due = nil,
    _aad_attempts = 0,
}

mq.event('HB_AutoDefendEnabled', "#*#Bot 'auto defend' is now enabled#*#", function()
    state.auto_defend_enabled = true
end)
mq.event('HB_AutoDefendDisabled', "#*#Bot 'auto defend' is now disabled#*#", function()
    state.auto_defend_enabled = false
end)

local runner = {
    tasks = nil,
    index = 0,
    due = 0,
}

local config = {
    window = {
        opacity = 0.85, -- 0..1
        bg = {r=0.10,g=0.10,b=0.10,a=1.0},
        border = {r=0.30,g=0.30,b=0.30,a=0.6},
        use_custom_bg = true,
        unobtrusive = true,
        padding = 4,
        rounding = 8,
    },
    ui = {
        compact_color = true,      -- use compact ColorEdit4 instead of full wheel inline
        picker_width = 180,        -- width hint for inline color wheels
    },
    buttons = {
        width = 110,
        height = 28,
        rounding = 6.0,
        border_size = 0.0,
        spacing = 5.0,
        shape = 'square', -- 'square' or 'circle'
        colors = {
            normal = {r=0.35,g=0.35,b=0.35,a=0.90},
            hovered = {r=0.45,g=0.45,b=0.45,a=0.95},
            active = {r=0.28,g=0.28,b=0.28,a=1.00},
            text = {r=0.95,g=0.95,b=0.95,a=1.0},
        },
        use_custom_colors = true,
    },
    hotbar = {
        items = nil, -- array of repository ids in draw order
    },
}

local function get_time_ms()
    if mq.gettime then
        local ok, v = pcall(mq.gettime)
        if ok and v then return v end
    end
    return math.floor((os.clock() or 0) * 1000)
end

local function schedule_actions(actions)
    if not actions or #actions == 0 then return end
    runner.tasks = actions
    runner.index = 1
    runner.due = get_time_ms()
end

local function process_runner()
    if not runner.tasks or runner.index <= 0 then return end
    local now = get_time_ms()
    if now < runner.due then return end
    if runner.index > #runner.tasks then
        runner.tasks = nil
        runner.index = 0
        runner.due = 0
        return
    end
    local a = runner.tasks[runner.index]
    runner.index = runner.index + 1
    if a and a.type == 'cmd' and a.text then
        mq.cmd(a.text)
        runner.due = now
    elseif a and a.type == 'delay' and a.ms then
        local ms = tonumber(a.ms) or 0
        runner.due = now + ms
    else
        runner.due = now
    end
end

local function build_spawn_missing_actions()
    local actions = {}
    local missing = 0
    local in_raid = false
    local in_group = false

    local function first_name(name)
        if not name then return nil end
        local f = tostring(name):match('^(%S+)')
        return f or name
    end

    local function get_member_name(member)
        if not member then return nil end
        local nm
        local ok1, v1 = pcall(function() return member.Name and member.Name() end)
        if ok1 and v1 and v1 ~= '' then nm = v1 end
        if not nm then
            local ok2, v2 = pcall(function() return member.CleanName and member.CleanName() end)
            if ok2 and v2 and v2 ~= '' then nm = v2 end
        end
        return nm
    end

    local me_name = nil
    pcall(function() me_name = mq.TLO.Me and mq.TLO.Me.CleanName and mq.TLO.Me.CleanName() end)

    local names = {}
    local seen = {}

    local raidCount = 0
    local okRaid, rc = pcall(function()
        return (mq.TLO.Raid and mq.TLO.Raid.Members and tonumber(mq.TLO.Raid.Members() or 0)) or 0
    end)
    raidCount = (okRaid and rc) or 0
    if raidCount and raidCount > 0 then
        in_raid = true
        for i=1, raidCount do
            local mem = mq.TLO.Raid and mq.TLO.Raid.Member and mq.TLO.Raid.Member(i)
            local nm = get_member_name(mem)
            if nm and nm ~= '' then
                if not (me_name and first_name(nm) == first_name(me_name)) then
                    if not seen[nm] then table.insert(names, nm); seen[nm] = true end
                end
            end
        end
    end

    local groupCount = 0
    local okGrp, gc = pcall(function()
        return (mq.TLO.Group and mq.TLO.Group.Members and tonumber(mq.TLO.Group.Members() or 0)) or 0
    end)
    groupCount = (okGrp and gc) or 0
    if groupCount and groupCount > 1 then
        in_group = true
        for i=1, groupCount do
            local mem = mq.TLO.Group and mq.TLO.Group.Member and mq.TLO.Group.Member(i)
            local nm = get_member_name(mem)
            if nm and nm ~= '' then
                if not (me_name and first_name(nm) == first_name(me_name)) then
                    if not seen[nm] then table.insert(names, nm); seen[nm] = true end
                end
            end
        end
    end

    local checked = 0
    local missing_names = {}

    local function add_spawn(name)
        if not name or name == '' then return end
        local fname = first_name(name)
        table.insert(actions, {type='cmd', text='/say ^botspawn '..fname})
        table.insert(actions, {type='delay', ms=400})
        missing = missing + 1
        table.insert(missing_names, fname)
    end

    local function spawn_if_missing(name)
        if not name or name == '' then return end
        checked = checked + 1
        local exact = '='..name
        local present = false
        local okS, s = pcall(function()
            return mq.TLO.Spawn and mq.TLO.Spawn(exact)
        end)
        if okS and s then
            local okID, id = pcall(function() return s.ID and s.ID() end)
            if okID and tonumber(id or 0) > 0 then
                present = true
            else
                local okStr, sval = pcall(function() return s() end)
                if okStr and sval ~= nil and sval ~= false and sval ~= '' then
                    present = true
                end
            end
        end
        if not present then add_spawn(name) end
    end

    for _, nm in ipairs(names) do
        spawn_if_missing(nm)
    end

    if missing == 0 then
        if in_raid or in_group then
            table.insert(actions, {type='cmd', text=('/echo No missing bots to spawn. Scanned %d name(s).'):format(checked)})
        else
            table.insert(actions, {type='cmd', text='/echo Not in a raid or group.'})
        end
    else
        table.insert(actions, {type='cmd', text=('/echo Spawning %d missing bot(s): %s'):format(missing, table.concat(missing_names, ', '))})
    end

    return actions
end

local function request_auto_defend_status(delay_ms)
    mq.cmd("/say ^oo current")
    state._aad_query_due = get_time_ms() + (tonumber(delay_ms) or 400)
    state._aad_attempts = 0
end

local function try_read_auto_defend_status()
    if not state._aad_query_due then return end
    local now = get_time_ms()
    if now < state._aad_query_due then return end
    state._aad_attempts = (state._aad_attempts or 0) + 1
    local w = mq.TLO.Window and mq.TLO.Window('LargeDialogWindow')
    local tb = w and w.Child and w.Child('LDW_TextBox')
    local txt
    local ok, res = pcall(function()
        if tb and tb.Text then return tb.Text() end
        return nil
    end)
    if ok then txt = res end
    if type(txt) == 'string' and txt ~= '' then
        local low = txt:lower()
        if low:find("auto%s*defend.-enabled") then
            state.auto_defend_enabled = true
            state._aad_query_due = nil
            pcall(function() if w and w() and w.Open() then w.DoClose() end end)
            return
        elseif low:find("auto%s*defend.-disabled") then
            state.auto_defend_enabled = false
            state._aad_query_due = nil
            pcall(function() if w and w() and w.Open() then w.DoClose() end end)
            return
        end
    end
    if state._aad_attempts >= 10 then
        state._aad_query_due = nil
        return
    end
    state._aad_query_due = now + 300
end

local function get_script_dir()
    local info = debug.getinfo(1, 'S')
    local src = info and info.source or ''
    if src:sub(1,1) == '@' then src = src:sub(2) end
    local dir = src:match('^(.*[\\/])')
    return dir or ''
end

local CONFIG_PATH = config_paths.get_path('commandsui_config.json')
local LEGACY_CONFIG_PATH = get_script_dir() .. 'commandsui_config.json'

local function deep_merge(dst, src)
    if type(dst) ~= 'table' or type(src) ~= 'table' then return dst end
    for k,v in pairs(src) do
        if type(v) == 'table' then
            dst[k] = dst[k] or {}
            deep_merge(dst[k], v)
        else
            dst[k] = v
        end
    end
    return dst
end

local function clamp01(x)
    if x == nil then return 0 end
    if x < 0 then return 0 elseif x > 1 then return 1 end
    return x
end

local function save_config()
    if not has_json then return false end
    local encoded = json.encode(config, {indent=true})
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
    local decoded, _, err = json.decode(content)
    if not decoded or err then return false end
    deep_merge(config, decoded)
    config.window.opacity = clamp01(tonumber(config.window.opacity or 1.0) or 1.0)
    if loaded_from_legacy then pcall(save_config) end
    return true
end

pcall(load_config)

if config.repo_custom and type(config.repo_custom) == 'table' then
    repo.register_many(config.repo_custom)
end

if not config.hotbar or not config.hotbar.items or #config.hotbar.items == 0 then
    config.hotbar = config.hotbar or {}
    config.hotbar.items = {
        'attack_spawned','backoff','hold','guard_here','clearcamp_callback','auto_assist_toggle','summon_to_me','spawn_missing_party_bots'
    }
end

function M.get_state()
    return state
end

function M.get_config()
    return config
end

function M.schedule_actions(actions)
    schedule_actions(actions)
end

function M.process_runner()
    process_runner()
end

function M.build_spawn_missing_actions()
    return build_spawn_missing_actions()
end

function M.request_auto_defend_status(delay_ms)
    request_auto_defend_status(delay_ms)
end

function M.try_read_auto_defend_status()
    try_read_auto_defend_status()
end

function M.save_config()
    return save_config()
end

function M.load_config()
    return load_config()
end

function M.clamp01(x)
    return clamp01(x)
end

return M
