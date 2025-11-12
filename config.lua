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
    if not ok or not lfs then return end
    local attr = lfs.attributes(path)
    if attr and attr.mode == 'directory' then return end
    pcall(lfs.mkdir, path)
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
