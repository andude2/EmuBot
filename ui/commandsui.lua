local mq = require('mq')
local ImGui = require('ImGui')
local Icons = require('mq.icons')
local repo = require('ui.command_repo')
local logic = require('ui.commandsui_logic')

-- Bot HotBar UI module for EmuBot
-- Usage from your main script:
--   local commandsui = require('ui.commandsui')
--   commandsui.start()

local M = {}

local config = logic.get_config()
local logic_state = logic.get_state()
local clamp01 = logic.clamp01

local state = {
    open = true,
    showSettings = false,
}

local function push_styles()
    -- Window background
    if config.window.use_custom_bg then
        local bg = config.window.bg
        local alpha = clamp01(config.window.opacity) * (bg.a or 1.0)
        ImGui.PushStyleColor(ImGuiCol.WindowBg, bg.r or 0.1, bg.g or 0.1, bg.b or 0.1, alpha)
        local border = config.window.border
        ImGui.PushStyleColor(ImGuiCol.Border, (border.r or 0.4), (border.g or 0.4), (border.b or 0.4), (border.a or 0.8))
    end
    -- Compact window padding/rounding
    ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, (config.window.padding or 4), (config.window.padding or 4))
    ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, (config.window.rounding or 8))
    -- Button colors
    if config.buttons.use_custom_colors then
        local c = config.buttons.colors
        ImGui.PushStyleColor(ImGuiCol.Button, c.normal.r, c.normal.g, c.normal.b, c.normal.a)
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, c.hovered.r, c.hovered.g, c.hovered.b, c.hovered.a)
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, c.active.r, c.active.g, c.active.b, c.active.a)
        ImGui.PushStyleColor(ImGuiCol.Text, c.text.r, c.text.g, c.text.b, c.text.a)
    end
    -- Shape
    ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, config.buttons.rounding)
    ImGui.PushStyleVar(ImGuiStyleVar.FrameBorderSize, config.buttons.border_size)
    ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, config.buttons.spacing, config.buttons.spacing)
end

local function pop_styles()
    -- Pop in reverse order of push
    ImGui.PopStyleVar(5)
    if config.buttons.use_custom_colors then ImGui.PopStyleColor(4) end
    if config.window.use_custom_bg then ImGui.PopStyleColor(2) end
end

local function draw_settings_window()
    if not state.showSettings then return end
    ImGui.SetNextWindowSize(640, 540, ImGuiCond.FirstUseEver)
    -- Apply same theming as HotBar
    push_styles()
    local isOpen, shouldDraw = ImGui.Begin('Bot HotBar Settings', true, ImGuiWindowFlags.None)
    if not isOpen then
        state.showSettings = false
        ImGui.End()
        pop_styles()
        return
    end
    if not shouldDraw then ImGui.End(); pop_styles(); return end

    -- Left nav (sections & keys)
    local leftWidth = 220
    ImGui.BeginChild('##HB_LeftNav', leftWidth, 0, ImGuiChildFlags.Border)
    ImGui.Text('Sections & Keys')
    ImGui.Separator()

    state._selGroup = state._selGroup or 'Appearance'
    state._selItem = state._selItem or 'Window'

    -- Appearance tree
    if ImGui.CollapsingHeader('Appearance', ImGuiTreeNodeFlags.DefaultOpen) then
        local items = {'Window','Buttons','Colors'}
        for _, name in ipairs(items) do
            local selected = (state._selGroup=='Appearance' and state._selItem==name)
            if ImGui.Selectable(name, selected) then
                state._selGroup, state._selItem = 'Appearance', name
            end
        end
    end

    -- HotBar tree
    if ImGui.CollapsingHeader('HotBar', ImGuiTreeNodeFlags.DefaultOpen) then
        local items = {'Manage HotBar','Create Custom','Repository'}
        for _, name in ipairs(items) do
            local selected = (state._selGroup=='HotBar' and state._selItem==name)
            if ImGui.Selectable(name, selected) then
                state._selGroup, state._selItem = 'HotBar', name
            end
        end
        -- Repository categories nested
        if state._selItem=='Repository' then
            local cats = {}
            for _, it in ipairs(repo.list()) do
                local c = it.category or 'Uncategorized'
                cats[c] = true
            end
            local catList = {}
            for c,_ in pairs(cats) do table.insert(catList, c) end
            table.sort(catList)
            if ImGui.TreeNode('Categories') then
                for _, c in ipairs(catList) do
                    local selected = (state._repoCategory == c)
                    if ImGui.Selectable('  '..c, selected) then
                        state._repoCategory = c
                    end
                end
                ImGui.TreePop()
            end
        end
    end

    -- Utils tree (placeholder for future)
    if ImGui.CollapsingHeader('Utils', ImGuiTreeNodeFlags.None) then
        local items = {'About'}
        for _, name in ipairs(items) do
            local selected = (state._selGroup=='Utils' and state._selItem==name)
            if ImGui.Selectable(name, selected) then
                state._selGroup, state._selItem = 'Utils', name
            end
        end
    end

    ImGui.EndChild()

    ImGui.SameLine()

    -- Right content
    ImGui.BeginChild('##HB_RightPane', 0, 0, ImGuiChildFlags.Border)

    local function section_window()
        ImGui.Text('Window')
        local o = config.window.opacity
        local newVal, changed = ImGui.SliderFloat('Opacity', o, 0.10, 1.00)
        if changed then config.window.opacity = clamp01(newVal) end
    end

    local function section_buttons()
        ImGui.Text('Shape')
        local shapeOptions = {'Square','Pill','Circle'}
        local shapeKeyToIndex = {square=1, pill=2, circle=3}
        local indexToShapeKey = {'square','pill','circle'}
        local currentShapeIdx = shapeKeyToIndex[tostring(config.buttons.shape or 'square')] or 1
        local selIdx, selChanged = ImGui.Combo('Preset', currentShapeIdx, shapeOptions)
        if selChanged and selIdx then config.buttons.shape = indexToShapeKey[selIdx] or 'square' end
        ImGui.Separator()
        ImGui.Text('Sizing')
        local bw, bh = config.buttons.width, config.buttons.height
        local nv, ch = ImGui.SliderFloat('Width', bw, 60, 220); if ch then config.buttons.width = nv end
        nv, ch = ImGui.SliderFloat('Height', bh, 24, 80); if ch then config.buttons.height = nv end
        nv, ch = ImGui.SliderFloat('Rounding', config.buttons.rounding, 0, 20); if ch then config.buttons.rounding = nv end
        nv, ch = ImGui.SliderFloat('Border Size', config.buttons.border_size, 0, 3); if ch then config.buttons.border_size = nv end
        nv, ch = ImGui.SliderFloat('Spacing', config.buttons.spacing, 0, 16); if ch then config.buttons.spacing = nv end
    end

    local function section_colors()
        ImGui.Text('Colors')
        local btnFlags = bit32.bor(ImGuiColorEditFlags.NoInputs, ImGuiColorEditFlags.NoLabel, ImGuiColorEditFlags.NoOptions, ImGuiColorEditFlags.AlphaBar, ImGuiColorEditFlags.DisplayRGB, ImGuiColorEditFlags.InputRGB)
        local function color_button(label, coltbl)
            ImGui.AlignTextToFramePadding(); ImGui.Text(label); ImGui.SameLine()
            local col = {coltbl.r, coltbl.g, coltbl.b, coltbl.a}
            local out, used = ImGui.ColorEdit4('##'..label..'_btn', col, btnFlags)
            if used and type(out)=='table' then coltbl.r, coltbl.g, coltbl.b, coltbl.a = out[1] or 0, out[2] or 0, out[3] or 0, out[4] or 1 end
        end
        color_button('Button', config.buttons.colors.normal)
        color_button('Hovered', config.buttons.colors.hovered)
        color_button('Active', config.buttons.colors.active)
        color_button('Text', config.buttons.colors.text)
    end

    local function section_manage_hotbar()
        ImGui.Text('Manage HotBar')
        if ImGui.BeginTable('HotBarItems', 3, bit32.bor(ImGuiTableFlags.RowBg, ImGuiTableFlags.BordersOuter, ImGuiTableFlags.BordersV, ImGuiTableFlags.Resizable)) then
            ImGui.TableSetupColumn('Item', ImGuiTableColumnFlags.WidthStretch)
            ImGui.TableSetupColumn('Order', ImGuiTableColumnFlags.WidthFixed, 90)
            ImGui.TableSetupColumn('Remove', ImGuiTableColumnFlags.WidthFixed, 80)
            ImGui.TableHeadersRow()
            local toRemove=nil
            for i,id in ipairs(config.hotbar.items or {}) do
                local it = repo.get(id)
                ImGui.TableNextRow(); ImGui.TableNextColumn(); ImGui.Text(it and it.label or id)
                ImGui.TableNextColumn(); ImGui.PushID('order'..i)
                if ImGui.SmallButton('Up') and i>1 then config.hotbar.items[i],config.hotbar.items[i-1]=config.hotbar.items[i-1],config.hotbar.items[i] end
                ImGui.SameLine()
                if ImGui.SmallButton('Down') and i<#config.hotbar.items then config.hotbar.items[i],config.hotbar.items[i+1]=config.hotbar.items[i+1],config.hotbar.items[i] end
                ImGui.PopID(); ImGui.TableNextColumn(); ImGui.PushID('rm'..i)
                if ImGui.SmallButton('Remove') then toRemove=i end
                ImGui.PopID()
            end
            if toRemove then table.remove(config.hotbar.items,toRemove) end
            ImGui.EndTable()
        end
    end

    local function section_create_custom()
        ImGui.Text('Create Custom Button')
        state._newLabel = state._newLabel or ''; state._newCategory = state._newCategory or 'Custom'; state._newDesc = state._newDesc or ''; state._newCommands = state._newCommands or ''; state._addToHotbar = (state._addToHotbar==nil) and true or state._addToHotbar; state._newId = state._newId or ''
        state._newLabel,_=ImGui.InputText('Label',state._newLabel)
        state._newCategory,_=ImGui.InputText('Category',state._newCategory)
        state._newDesc,_=ImGui.InputText('Description',state._newDesc)
        ImGui.Text('Commands (one per line). Use "delay <ms>" for pauses')
        local h=100; local w=math.min(700,(ImGui.GetWindowWidth() or 700)*0.95)
        state._newCommands,_=ImGui.InputTextMultiline('##custom_cmds',state._newCommands,ImVec2(w,h))
        state._addToHotbar,_=ImGui.Checkbox('Add to HotBar after saving',state._addToHotbar)
        if ImGui.Button('Save Custom Button') then
            local label=(state._newLabel or ''):match('^%s*(.-)%s*$'); local cmds=state._newCommands or ''
            if label~='' and cmds~='' then
                local actions={}
                for line in cmds:gmatch('[^\r\n]+') do
                    local t=line:match('^%s*(.-)%s*$')
                    if t~='' then
                        local dms=t:match('^delay%s+(%d+)$') or t:match('^sleep%s+(%d+)$')
                        if dms then table.insert(actions,{type='delay',ms=tonumber(dms)})
                        else table.insert(actions,{type='cmd',text=t}) end
                    end
                end
                if #actions>0 then
                    local base=(state._newId~='' and state._newId) or label:lower():gsub('[^%w]+','_')
                    local id=base
                    local s=1
                    while repo.get(id) do id=base..'_'..tostring(s); s=s+1 end
                    local item={id=id,label=label,icon=nil,category=state._newCategory or 'Custom',description=state._newDesc or '',actions=actions}
                    config.repo_custom=config.repo_custom or {}
                    table.insert(config.repo_custom,item)
                    repo.register(item)
                    logic.save_config()
                    if state._addToHotbar then
                        config.hotbar.items=config.hotbar.items or {}
                        table.insert(config.hotbar.items,id)
                    end
                    state._newLabel=''; state._newCategory='Custom'; state._newDesc=''; state._newCommands=''; state._newId=''
                end
            end
        end
    end

    local function section_repository()
        local query = state._repoQuery or ''
        local newQuery, changed = ImGui.InputTextWithHint('##repoSearch', 'Search repository...', query)
        if changed then state._repoQuery = newQuery or '' end
        local list = repo.search(state._repoQuery)
        -- Group by category
        local groups = {}
        for _, it in ipairs(list) do
            local c = it.category or 'Uncategorized'
            groups[c] = groups[c] or {}
            table.insert(groups[c], it)
        end
        -- Optional filter by left-selected category
        local orderedCats = {}
        for c,_ in pairs(groups) do table.insert(orderedCats, c) end
        table.sort(orderedCats)
        for _, cat in ipairs(orderedCats) do
            if (not state._repoCategory) or state._repoCategory == cat then
                if ImGui.CollapsingHeader(cat, ImGuiTreeNodeFlags.DefaultOpen) then
                    if ImGui.BeginTable('Repo_'..cat, 4, bit32.bor(ImGuiTableFlags.RowBg, ImGuiTableFlags.BordersOuter, ImGuiTableFlags.BordersV, ImGuiTableFlags.Resizable)) then
                        ImGui.TableSetupColumn('Label', ImGuiTableColumnFlags.WidthStretch)
                        ImGui.TableSetupColumn('Category', ImGuiTableColumnFlags.WidthFixed, 120)
                        ImGui.TableSetupColumn('Add', ImGuiTableColumnFlags.WidthFixed, 80)
                        ImGui.TableSetupColumn('Do It', ImGuiTableColumnFlags.WidthFixed, 80)
                        ImGui.TableHeadersRow()
                        local exists = {}; for _, id in ipairs(config.hotbar.items or {}) do exists[id]=true end
                        for _, it in ipairs(groups[cat]) do
                            ImGui.TableNextRow(); ImGui.TableNextColumn(); ImGui.Text(it.label); if it.description and it.description~='' and ImGui.IsItemHovered() then ImGui.SetTooltip(it.description) end
                            ImGui.TableNextColumn(); ImGui.Text(it.category or '-')
                            ImGui.TableNextColumn(); ImGui.PushID('add_'..it.id)
                            local disabled = exists[it.id]; if disabled then ImGui.BeginDisabled(true) end
                            if ImGui.SmallButton('Add') and not disabled then table.insert(config.hotbar.items, it.id) end
                            if disabled then ImGui.EndDisabled() end
                            ImGui.PopID()
                            -- Do It button to execute the command/actions immediately
                            ImGui.TableNextColumn(); ImGui.PushID('do_'..it.id)
                            if ImGui.SmallButton('Do It') then
                                if it.id == 'spawn_missing_party_bots' then
                                    local a = logic.build_spawn_missing_actions()
                                    if a and #a > 0 then logic.schedule_actions(a) end
                                else
                                    if it.actions and #it.actions > 0 then logic.schedule_actions(it.actions) end
                                end
                            end
                            ImGui.PopID()
                        end
                        ImGui.EndTable()
                    end
                end
            end
        end
    end

    -- Dispatch by selection
    if state._selGroup=='Appearance' and state._selItem=='Window' then section_window()
    elseif state._selGroup=='Appearance' and state._selItem=='Buttons' then section_buttons()
    elseif state._selGroup=='Appearance' and state._selItem=='Colors' then section_colors()
    elseif state._selGroup=='HotBar' and state._selItem=='Manage HotBar' then section_manage_hotbar()
    elseif state._selGroup=='HotBar' and state._selItem=='Create Custom' then section_create_custom()
    elseif state._selGroup=='HotBar' and state._selItem=='Repository' then section_repository()
    else
        ImGui.Text('Select a section on the left to configure the HotBar.')
    end

    ImGui.EndChild()

    ImGui.End()
    -- Pop theming styles
    pop_styles()
end

-- Helper: get U32 from color table
local function col_u32(c)
    return ImGui.GetColorU32(c.r or 1, c.g or 1, c.b or 1, c.a or 1)
end

-- Draw a custom shape button; returns true on click
local function draw_shape_button(id, label, shape, w, h, colors, border_col)
    local clicked = ImGui.InvisibleButton(id, w, h)
    local hovered = ImGui.IsItemHovered()
    local active = ImGui.IsItemActive()

    local min = ImGui.GetItemRectMin()
    local max = ImGui.GetItemRectMax()
    local cx = (min.x + max.x) * 0.5
    local cy = (min.y + max.y) * 0.5
    local dl = ImGui.GetWindowDrawList()

    local fill = colors.normal
    if active then fill = colors.active
    elseif hovered then fill = colors.hovered end

    local fillU32 = col_u32(fill)
    local borderU32 = border_col and col_u32(border_col) or ImGui.GetColorU32(1,1,1,0.25)

    if shape == 'diamond' then
        -- Diamond (rotated square) using explicit quad APIs
        local p1 = ImVec2(cx, min.y)
        local p2 = ImVec2(max.x, cy)
        local p3 = ImVec2(cx, max.y)
        local p4 = ImVec2(min.x, cy)
        dl:AddQuadFilled(p1, p2, p3, p4, fillU32)
        dl:AddQuad(p1, p2, p3, p4, borderU32, 1.0)
    elseif shape == 'hex' or shape == 'hexagon' then
        -- Regular hex approximated to square bounds
        local radius = math.min(w, h) * 0.5 * 0.95
        dl:AddNgonFilled(ImVec2(cx, cy), radius, fillU32, 6)
        dl:AddNgon(ImVec2(cx, cy), radius, borderU32, 6, 1.0)
    elseif shape == 'triangle_right' then
        -- Right-pointing triangle using triangle APIs
        local p1 = ImVec2(min.x, min.y)
        local p2 = ImVec2(max.x, cy)
        local p3 = ImVec2(min.x, max.y)
        dl:AddTriangleFilled(p1, p2, p3, fillU32)
        dl:AddTriangle(p1, p2, p3, borderU32, 1.0)
    else
        -- Fallback rounded rectangle
        local rounding = 0
        if shape == 'pill' then rounding = (h or 0) * 0.5
        elseif shape == 'rounded' then rounding = config.buttons.rounding or 6
        else rounding = config.buttons.rounding or 0 end
        dl:AddRectFilled(min, max, fillU32, rounding)
        dl:AddRect(min, max, borderU32, rounding)
    end

    -- Optional: tooltip shows the label (avoid draw-list text on custom shapes)
    if label and label ~= '' and ImGui.IsItemHovered() then
        ImGui.SetTooltip(label)
    end

    return clicked
end

local function draw_hotbar()
    -- Optional: size hint on first use
    ImGui.SetNextWindowSize(750, 70, ImGuiCond.FirstUseEver)
    push_styles()
    local flags = ImGuiWindowFlags.AlwaysAutoResize
    if config.window.unobtrusive then
        flags = bit32.bor(flags,
            ImGuiWindowFlags.NoTitleBar,
            ImGuiWindowFlags.NoResize,
            ImGuiWindowFlags.NoScrollbar,
            ImGuiWindowFlags.NoScrollWithMouse,
            ImGuiWindowFlags.NoCollapse)
    end
    if ImGui.Begin('Bot HotBar##EmuBotHotBar', state.open, flags) then
        -- Top row: gear icon settings toggle (Font Awesome) and raid HUD toggle
        if ImGui.SmallButton(Icons.FA_COG) then
            state.showSettings = not state.showSettings
        end
        if ImGui.IsItemHovered() then ImGui.SetTooltip('Settings') end
        
        -- Small 'r' button for raid HUD toggle
        ImGui.SameLine(0, 3) -- Small spacing between buttons
        if ImGui.SmallButton(Icons.FA_DOT_CIRCLE_O) then
            -- Toggle the raid HUD
            local ok, raid_hud = pcall(require, 'ui.raid_hud')
            if ok and raid_hud and raid_hud.toggle then
                raid_hud.toggle()
            else
                mq.cmd('/ebraid toggle')
            end
        end
        if ImGui.IsItemHovered() then ImGui.SetTooltip('Toggle Raid HUD (r)') end
        
        ImGui.Separator()

        local W = tonumber(config.buttons.width) or 110
        local H = tonumber(config.buttons.height) or 28
        local shape = tostring(config.buttons.shape or 'square')
        if shape == 'rounded' then shape = 'square' end -- backward-compat: treat old 'rounded' as square with rounding

        -- Helper to render one button according to shape
        local function render_btn(label)
            if shape == 'circle' then
                local S = math.max(16, math.min(W, H))
                ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, S * 0.5)
                local clicked = ImGui.Button(label, S, S)
                ImGui.PopStyleVar(1)
                return clicked
            else
                -- Square or Pill via default button with rounding override
                local rounding = (shape == 'pill') and (H * 0.5) or (config.buttons.rounding or 0)
                local pushed = false
                if rounding and rounding > 0 then
                    ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, rounding)
                    pushed = true
                end
                local clicked = ImGui.Button(label, W, H)
                if pushed then ImGui.PopStyleVar(1) end
                return clicked
            end
        end

        -- Render hotbar items from repository
        local perRow = 4
        local count = 0
        for _, id in ipairs(config.hotbar.items or {}) do
            local it = repo.get(id)
            local baseLabel = (it and it.label) or id
            local label = baseLabel
            -- Constant label for auto-assist toggle; rely on color to indicate state
            if id == 'auto_assist_toggle' then
                label = 'Auto Assist'
            end
            -- Per-button color override for auto assist toggle
            local pushedColor = false
            if id == 'auto_assist_toggle' and logic_state.auto_defend_enabled ~= nil then
                if logic_state.auto_defend_enabled == true then
                    -- Green
                    ImGui.PushStyleColor(ImGuiCol.Button, 0.2, 0.7, 0.2, 0.9)
                    ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.3, 0.8, 0.3, 1.0)
                    ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.1, 0.6, 0.1, 1.0)
                else
                    -- Red
                    ImGui.PushStyleColor(ImGuiCol.Button, 0.7, 0.2, 0.2, 0.9)
                    ImGui.PushStyleColor(ImGuiCol.ButtonHovered, 0.8, 0.3, 0.3, 1.0)
                    ImGui.PushStyleColor(ImGuiCol.ButtonActive, 0.6, 0.1, 0.1, 1.0)
                end
                pushedColor = true
            end

            if render_btn(label) then
                -- Special handler for spawn-missing hotbutton
                if id == 'spawn_missing_party_bots' then
                    local a = logic.build_spawn_missing_actions()
                    if a and #a > 0 then logic.schedule_actions(a) end
                else
                    -- Schedule actions non-blocking to avoid crashes in UI thread
                    if it and it.actions then
                        logic.schedule_actions(it.actions)
                        -- If this is the auto-assist toggle, rely on chat events to update state (no LDW reopen)
                    end
                end
            end

            if pushedColor then ImGui.PopStyleColor(3) end

            count = count + 1
            -- Tooltip with commands
            if ImGui.IsItemHovered() and it and it.actions then
                ImGui.BeginTooltip()
                ImGui.Text(label)
                ImGui.Separator()
                for ai, a in ipairs(it.actions) do
                    if a.type == 'cmd' then
                        ImGui.Text(string.format('%d. %s', ai, a.text))
                    elseif a.type == 'delay' then
                        ImGui.Text(string.format('%d. delay %d', ai, tonumber(a.ms) or 0))
                    end
                end
                ImGui.EndTooltip()
            end
            if (count % perRow) ~= 0 then
                ImGui.SameLine()
            end
        end
    end
    -- Process any scheduled actions (non-blocking)
    logic.process_runner()
    logic.try_read_auto_defend_status()

    ImGui.End()
    pop_styles()
    -- Draw settings window if toggled
    draw_settings_window()
end

function M.start()
    -- Query current auto-defend status on startup
    logic.request_auto_defend_status(600)
    -- Register the ImGui draw callback (id must be unique per script)
    mq.imgui.init('emubot_hotbar', draw_hotbar)
end

function M.stop()
    state.open = false
end

function M.toggle()
    state.open = not state.open
end

function M.set_visible(b)
    state.open = not not b
end

function M.is_visible()
    return state.open and true or false
end

return M
