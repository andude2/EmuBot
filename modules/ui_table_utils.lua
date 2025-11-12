local ImGuiSortDirection = ImGuiSortDirection

local function try_call(method, ...)
    if type(method) == 'function' then
        local ok, result = pcall(method, ...)
        if ok then return result end
    end
    return nil
end

local function get_sort_spec(sortSpecs, index)
    if not sortSpecs then return nil end
    local specsField = sortSpecs.Specs

    if type(specsField) == 'function' then
        local spec = try_call(specsField, sortSpecs, index)
        if not spec then
            spec = try_call(specsField, sortSpecs, index - 1)
        end
        if spec then return spec end
    elseif type(specsField) == 'table' then
        if specsField[index] ~= nil then return specsField[index] end
        if specsField[index - 1] ~= nil then return specsField[index - 1] end
    elseif specsField ~= nil then
        local ok, spec = pcall(function() return specsField[index] end)
        if ok and spec ~= nil then return spec end
        ok, spec = pcall(function() return specsField[index - 1] end)
        if ok and spec ~= nil then return spec end
    end

    if type(sortSpecs.SpecsGet) == 'function' then
        local spec = try_call(sortSpecs.SpecsGet, sortSpecs, index)
        if not spec then
            spec = try_call(sortSpecs.SpecsGet, sortSpecs, index - 1)
        end
        if spec then return spec end
    end
    if type(sortSpecs.SpecsIndex) == 'function' then
        local spec = try_call(sortSpecs.SpecsIndex, sortSpecs, index)
        if not spec then
            spec = try_call(sortSpecs.SpecsIndex, sortSpecs, index - 1)
        end
        if spec then return spec end
    end
    if type(sortSpecs.Specs) == 'table' then
        return sortSpecs.Specs[index]
    end
    if type(sortSpecs) == 'table' then
        return sortSpecs[index]
    end
    return nil
end

local function applyTableSort(data, sortSpecs, accessors)
    if not sortSpecs or not data then return end

    local specsCount = sortSpecs.SpecsCount
    if type(specsCount) == 'function' then
        specsCount = try_call(specsCount, sortSpecs) or 0
    end
    specsCount = tonumber(specsCount) or 0
    if specsCount == 0 then return end

    table.sort(data, function(a, b)
        for i = 1, specsCount do
            local spec = get_sort_spec(sortSpecs, i)
            if spec then
                local colIdx = (spec.ColumnIndex or 0) + 1
                local accessor = accessors and accessors[colIdx]
                if accessor then
                    local av = accessor(a)
                    local bv = accessor(b)
                    if av ~= bv then
                        if type(av) == 'number' and type(bv) == 'number' then
                            if spec.SortDirection == ImGuiSortDirection.Descending then
                                return (av or 0) > (bv or 0)
                            else
                                return (av or 0) < (bv or 0)
                            end
                        else
                            av = av and tostring(av) or ''
                            bv = bv and tostring(bv) or ''
                            local aLower = av:lower()
                            local bLower = bv:lower()
                            if aLower ~= bLower then
                                local cmp = aLower < bLower
                                if spec.SortDirection == ImGuiSortDirection.Descending then
                                    return not cmp
                                else
                                    return cmp
                                end
                            end
                        end
                    end
                end
            end
        end
        return false
    end)

    if type(sortSpecs.ClearDirty) == 'function' then
        try_call(sortSpecs.ClearDirty, sortSpecs)
    elseif sortSpecs.SpecsDirty ~= nil then
        sortSpecs.SpecsDirty = false
    end
end

return {
    applyTableSort = applyTableSort,
}
