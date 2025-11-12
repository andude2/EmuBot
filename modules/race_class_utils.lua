-- EmuBot race/class utility mapping and helpers
-- Provides validation and allowed-class lookup for bot creation

local M = {}

-- Short-code to pretty name maps
M.RACE_NAMES = {
  HUM = 'Human', BAR = 'Barbarian', ERU = 'Erudite', ELF = 'Wood Elf', HIE = 'High Elf',
  DEF = 'Dark Elf', HEF = 'Half Elf', DWF = 'Dwarf', TRL = 'Troll', OGR = 'Ogre',
  HFL = 'Halfling', GNM = 'Gnome', IKS = 'Iksar', VAH = 'Vah Shir', FRG = 'Froglok', DRK = 'Drakkin',
}

M.CLASS_NAMES = {
  WAR = 'Warrior', CLR = 'Cleric', PAL = 'Paladin', RNG = 'Ranger', SHD = 'Shadow Knight',
  DRU = 'Druid', MNK = 'Monk', BRD = 'Bard', ROG = 'Rogue', SHM = 'Shaman',
  NEC = 'Necromancer', WIZ = 'Wizard', MAG = 'Magician', ENC = 'Enchanter', BST = 'Beastlord', BER = 'Berserker',
}

-- Allowed class codes per race code (derived from user's utils.lua mapping)
M.ALLOWED_BY_RACE = {
  BAR = {'BST','BER','ROG','SHM','WAR'},
  DEF = {'CLR','ENC','MAG','NEC','ROG','SHD','WAR','WIZ'},
  DRK = {'BRD','CLR','DRU','ENC','MAG','MNK','NEC','PAL','RNG','ROG','SHD','WAR','WIZ'},
  DWF = {'BER','CLR','PAL','ROG','WAR'},
  ERU = {'CLR','ENC','MAG','NEC','PAL','SHD','WIZ'},
  FRG = {'CLR','MNK','NEC','PAL','ROG','SHD','SHM','WAR','WIZ'},
  GNM = {'CLR','ENC','MAG','NEC','PAL','ROG','SHD','WAR','WIZ'},
  HEF = {'BRD','DRU','PAL','RNG','ROG','WAR'},
  HFL = {'CLR','DRU','PAL','RNG','ROG','WAR'},
  HIE = {'CLR','ENC','MAG','PAL','WIZ'},
  HUM = {'BRD','CLR','DRU','ENC','MAG','MNK','NEC','PAL','RNG','ROG','SHD','WAR','WIZ'},
  IKS = {'BST','MNK','NEC','SHD','SHM','WAR'},
  OGR = {'BST','BER','SHD','SHM','WAR'},
  TRL = {'BST','BER','SHD','SHM','WAR'},
  VAH = {'BRD','BST','BER','ROG','SHM','WAR'},
  ELF = {'BRD','BST','DRU','RNG','ROG','WAR'}, -- Wood Elf
}

local function set_to_map(list)
  local t = {}
  for _, v in ipairs(list or {}) do t[v] = true end
  return t
end

-- Cached set views for quick validation
M._allowed_sets = {}
for race, list in pairs(M.ALLOWED_BY_RACE) do
  M._allowed_sets[race] = set_to_map(list)
end

function M.is_valid_combo(race_code, class_code)
  if not race_code or not class_code then return false end
  local set = M._allowed_sets[race_code]
  return set and set[class_code] and true or false
end

function M.allowed_classes_for_race(race_code)
  local list = M.ALLOWED_BY_RACE[race_code]
  if not list then return {} end
  -- Return a shallow copy to avoid external mutation
  local out = {}
  for _, v in ipairs(list) do table.insert(out, v) end
  return out
end

function M.allowed_races_for_class(class_code)
  if not class_code then return {} end
  local out = {}
  for race, list in pairs(M.ALLOWED_BY_RACE) do
    for _, c in ipairs(list) do
      if c == class_code then table.insert(out, race); break end
    end
  end
  return out
end

return M
