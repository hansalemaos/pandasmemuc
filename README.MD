# Automating memu emulator with pandas

## pip install pandasmemuc 

#### Tested against Windows 10 / Python 3.10 / Anaconda 


Memu Player and at least one Android instance must be installed https://www.memuplay.com/ 

Most of the command line stuff already implemented, documentation soon 

https://www.memuplay.com/blog/memucommand-reference-manual.html

https://www.memuplay.com/blog/wp-content/uploads/2016/02/MEmu-Command-Line-Management-Interface-Version-4.3.20_OSE.pdf



Example: 
	
```python


from pandasmemuc import MeMuc, phoneconfig
import pandas as pd

phoneconfig.phone_dataframe = pd.read_pickle("c:\\allphonedata.pkl") # optional
phoneconfig.mac_address_prefix = "52:54:00" 
df = MeMuc()
# df.create_vm_96().update_status()
df.import_vm(path=r"C:\ProgramData\anaconda3\envs\dfdir\memuimage.ova", name="mem38")
df.iloc[-1].bb_start()
df.iloc[-1].bb_installapp(r"C:\Users\hansc\Downloads\spotify-8-8-50-466.apk")
df.iloc[-1].bb_startapp('com.spotify.music')

# spoti = df.get_ui_automator_df(2)
# spoti = spoti.loc[(spoti.bb_resource_id == 'com.spotify.music:id/bottom_navigation_item_icon') & (spoti.bb_content_desc == 'Buscar')].iloc[0].ff_bb_tap_exact_center
# spoti = df.get_ui_automator_df(2)
# spoti.loc[spoti.bb_resource_id == 'com.spotify.music:id/find_search_field'].ff_bb_tap_exact_center.iloc[0]()
# df.bb_input_natural.iloc[0]('AC/DC')
# allbois.reindex(allbois.bb_text.str.len().sort_values().index).iloc[0].ff_bb_tap_exact_center()
# df.bb_adbtools.iloc[-1].aa_disable_notifications()
# df.bb_adbtools.iloc[-1].aa_force_stop('com.microvirt.memuime')
# df = m.get_ui_automator_df(0, save_screenshot=True) # check out https://github.com/hansalemaos/adbkit

```