[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/andude2/EmuBot)

Finally! A visual tool to help you keep track of your ^bots and their inventories.  

Drop this in your /lua folder, then run in game with a /lua run emubot.  ***NOTE***  If the folder has -main on it, you will need to rename the folder and delete -main off the end.  
Your file structure should look like <macroquest>/lua/emubot/init.lua.  It should NOT look like <macroquest>/lua/emubot/emubot/init.lua

![emubot 1](https://github.com/user-attachments/assets/a926e47f-205a-4d14-b0be-43ae7d532300)

At first run, I recommend running a "Scan All Bots", so that the script can cache all your inventories.

***NOTE*** If you currently have more bots made than your server allows to spawn, go ahead and turn "Camp After Scan?" to ON.  This will camp your bots so you can gather ALL the inventories.

Featuring an "Upgrade" option, which gives you a visual interface to swap out equipment on your bots with the click of a button.

![emutbot 2](https://github.com/user-attachments/assets/e9bf655b-edff-44ec-bb31-d54ba9beb3ea)

And slowly integrating Bot Management - you can see all your bots, and a handy little tool to make a NEW bot without having to remember class/race number combos! (**note - since some servers allow all classes/all races
I did not limit the combinations - YMMV)

![emubot 3](https://github.com/user-attachments/assets/cba9cf63-e9ba-4f56-80ea-bf682403a8e4)

Still a work in progress:

Group Management - easily create and spawn/invite a group.  I'm still working on this...will get raid stuff soon!

![emubot 4](https://github.com/user-attachments/assets/cfdce110-c9d4-4034-82ba-c743ec9de823)

Dependencies
- EmuBot uses SQLite for persistence via `lsqlite3`.
- On fresh MacroQuest installs, EmuBot will try to fetch `lsqlite3` automatically using `mq.PackageMan`.
- If auto-install fails, use your package manager to install `lsqlite3` and reload EmuBot.


