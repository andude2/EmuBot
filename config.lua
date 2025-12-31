local mq = require('mq')

local M = {}

local function normalize(path)
    if not path or path == '' then return nil end
    path = tostring(path):gsub('\\', '/')
    return path:gsub('/+$', '')
end

local function resolve_candidate(value)
    if not value then return nil end
    if type(value) == 'function' then
        local ok, result = pcall(value)
        if not ok then return nil end
        value = result
    end
    return normalize(value)
end

local function resolve_config_root()
    local dir

    if mq then
        dir = resolve_candidate(mq.configDir)
        if not dir and mq.TLO and mq.TLO.MacroQuest and mq.TLO.MacroQuest.Path then
            local ok, cfg = pcall(function()
                return mq.TLO.MacroQuest.Path('config')()
            end)
            if ok then dir = normalize(cfg) end
        end
        if not dir then
            dir = resolve_candidate(mq.luaDir)
        end
    end

    return dir or '.'
end

local function ensure_dir(path)
    local ok, lfs = pcall(require, 'lfs')
    if not ok or not lfs then
        print('[EmuBot Config] Warning: lfs module not available, cannot create directories')
        return false
    end

    local attr = lfs.attributes(path)
    if attr and attr.mode == 'directory' then
        return true
    end

    -- Split path into components and create recursively
    local parts = {}
    for part in path:gmatch('[^/\\]+') do
        table.insert(parts, part)
    end

    -- Build path incrementally
    local current = ''
    for i, part in ipairs(parts) do
        if i == 1 and path:match('^/') then
            current = '/' .. part
        elseif i == 1 then
            current = part
        else
            current = current .. '/' .. part
        end

        local attr = lfs.attributes(current)
        if not attr then
            local success, err = pcall(lfs.mkdir, current)
            if not success then
                print(string.format('[EmuBot Config] Failed to create directory: %s (Error: %s)', current, tostring(err)))
                return false
            end
        elseif attr.mode ~= 'directory' then
            print(string.format('[EmuBot Config] Path exists but is not a directory: %s', current))
            return false
        end
    end

    print(string.format('[EmuBot Config] Created config directory: %s', path))
    return true
end

function M.get_dir()
    local base = resolve_config_root()
    local dir = string.format('%s/EmuBot', base)
    ensure_dir(dir)
    return dir
end

function M.get_path(filename)
    if not filename or filename == '' then return M.get_dir() end
    return string.format('%s/%s', M.get_dir(), filename)
end

return M
