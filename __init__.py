import random
import sys
import regex
from flexible_partial import FlexiblePartialOwnName
from adbkit import ADBTools
import subprocess
import io

from reggisearch import search_values
from a_pandas_ex_apply_ignore_exceptions import pd_add_apply_ignore_exceptions
from subprocesskiller import subprocess_timeout
from a_pandas_ex_xml2df import pd_add_read_xml_files
import pandas as pd
from PrettyColorPrinter import add_printer
import os
import tempfile
from time import sleep

import requests
from touchtouch import touch
from isiter import isiter

add_printer(1)
pd_add_read_xml_files()
pd_add_apply_ignore_exceptions()
di = search_values(
    mainkeys=(
        g := r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\MEmu"
    ),
    subkeys=("DisplayIcon",),
)
memucfolder = (
    os.sep.join(
        (regex.findall('"([^"]+)"', di[g]["DisplayIcon"])[0].split(os.sep)[:-1])
    )
    + os.sep
)
memuc = memucfolder + "MEmuC.exe"
memumanage = os.sep.join(memuc.split(os.sep)[:-2] + ["MEmuHyperv", "MEmuManage.exe"])
adb_path = memucfolder + "adb.exe"
phoneconfig = sys.modules[__name__]
phoneconfig.phone_dataframe = pd.DataFrame()
phoneconfig.mac_address_prefix = "52:54:00"


def tempfolder_and_files(fileprefix="tmp_", numberoffiles=1, suffix=".bin", zfill=8):
    tempfolder = tempfile.TemporaryDirectory()
    tempfolder.cleanup()
    allfiles = []

    for fi in range(numberoffiles):
        tempfile____txtlist = os.path.join(
            tempfolder.name, f"{fileprefix}_{str(fi).zfill(zfill)}{suffix}"
        )
        allfiles.append(tempfile____txtlist)
        touch(tempfile____txtlist)

    return (
        [(k,) for k in allfiles],
        tempfolder.name.split(os.sep)[-1],
        tempfolder.name,
    )


def get_hosts_files(
    allhosts=(
        "https://adaway.org/hosts.txt",
        # "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        # "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        # "https://winhelp2002.mvps.org/hosts.txt",
    )
):
    if not isiter(allhosts):
        allhosts = [allhosts]
    allurls = []
    for url in allhosts:
        if os.path.exists(url):
            with open(url,mode='r',encoding='utf-8') as f:
                allurls.extend(
                    [
                        tuple(x.strip().split(maxsplit=1))
                        for x in f.read().splitlines()
                        if x and x[0] != "#"
                    ]
                )
        else:
            try:
                resp = requests.get(url)

                allurls.extend(
                    [
                        tuple(x.strip().split(maxsplit=1))
                        for x in resp.content.decode("utf-8").splitlines()
                        if x and x[0] != "#"
                    ]
                )
            except Exception as fe:
                print(fe)
                continue
    if len(allhosts) > 1:

        df = pd.DataFrame(sorted(list(set(allurls))))
        df = df.loc[(df[0] == "0.0.0.0") | (df[0] == "127.0.0.1")]
        df = df.drop(df.loc[(df[0] == "0.0.0.0") & (df[1] == "0.0.0.0")].index[0])

        newhostheader = """
        127.0.0.1 localhost
        127.0.0.1 localhost.localdomain
        127.0.0.1 local
        255.255.255.255 broadcasthost
        ::1 localhost
        ::1 ip6-localhost
        ::1 ip6-loopback
        fe80::1%lo0 localhost
        ff00::0 ip6-localnet
        ff00::0 ip6-mcastprefix
        ff02::1 ip6-allnodes
        ff02::2 ip6-allrouters
        ff02::3 ip6-allhosts
        0.0.0.0 0.0.0.0""".strip()

        newhost = "\n".join(
            [x[0] + " " + x[1] for x in zip(df[0].to_list(), df[1].to_list())]
        )
        newhost = newhostheader + "\n" + newhost
    else:
        newhost = '\n'.join([' '.join(list(x)) for x in allurls])
    fo = tempfolder_and_files(fileprefix="", numberoffiles=0, suffix="", zfill=0)[-1]
    if not os.path.exists(fo):
        os.makedirs(fo)
    hostfile = os.path.normpath(os.path.join(fo, "hosts"))
    with open(hostfile, "w", newline="\n", encoding="utf-8") as f:
        f.write(newhost)
    return hostfile


def connect_adb_tools(x):
    if "ERROR: " in x.aa_cpucap:
        ad = ADBTools(adb_path=adb_path, deviceserial=x.bb_serial)
        return ad
    return pd.NA


def run_subprocess(*args):
    return subprocess.run(
        [memuc, *[str(x) for x in args]], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def run_subprocess_manage(*args):
    return subprocess.run(
        [memumanage, *[str(x) for x in args]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def run_subprocess_manage_n(*args):
    alllist = []
    for x in args:
        if isinstance(x, int):
            alllist[-1] = alllist[-1] + str(x)
        else:
            alllist.append(str(x))

    return subprocess.run(
        [memumanage, *alllist], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def set_value(index, key, value):
    return subprocess.run(
        [memuc, "setconfigex", "-i", str(index), str(key), str(value)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def list_all_emulators():
    p = run_subprocess("listvms")
    i = io.StringIO(p.stdout.decode("utf-8").strip())
    dfr = pd.read_csv(
        i,
        header=None,
        names=["aa_index", "aa_title", "aa_handle", "aa_status", "aa_pid"],
        sep=",",
    )
    df2 = dfr.ds_apply_ignore(
        pd.NA,
        lambda x: subprocess.run(
            [memuc, "rename", "-i", str(x.aa_index), str(x.aa_title)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ),
        axis=1,
    )
    #print(df2)
    return dfr


def get_all_config(df):
    configcmds = [
        "cpus",
        "memory",
        "cpucap",
        "picturepath",
        "musicpath",
        "moviepath",
        "downloadpath",
        "is_full_screen",
        "is_hide_toolbar",
        # "turbo_mode",
        "graphics_render_mode",
        "enable_su",
        "enable_audio",
        "fps",
        "vkeyboard_mode",
        "sync_time",
        "phone_layout",
        "start_window_mode",
        "win_x",
        "win_y",
        "win_scaling_percent2",
        # "is_costumed_resolution",
        "resolution_width",
        "resolution_height",
        "vbox_dpi",
        "linenum",
        "imei",
        "imsi",
        "simserial",
        "microvirt_vm_brand",
        "microvirt_vm_manufacturer",
        "microvirt_vm_model",
        "selected_map",
        "longitude",
        "latitude",
    ]
    df2 = df.ds_apply_ignore(
        pd.NA,
        lambda x: [
            regex.sub(
                r"^Value:\s+",
                "",
                run_subprocess("getconfigex", "-i", str(x.aa_index), y)
                .stdout.decode("utf-8")
                .strip(),
            )
            for y in configcmds
        ],
        axis=1,
        result_type="expand",
    )
    df2.columns = [f"aa_{x}" for x in configcmds]
    df = pd.concat([df, df2], axis=1, ignore_index=False)
    df2 = df.ds_apply_ignore(
        pd.NA,
        lambda x: [
            FlexiblePartialOwnName(
                set_value, str(x[col]), True, str(x.aa_index), col[3:]
            )
            for col in df.columns
        ],
        axis=1,
        result_type="expand",
    )
    df2.columns = [f"set_{str(x)[3:]}" for x in df.columns]

    df["bb_remove"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "remove -i " + str(x), True, "remove", "-i", str(x)
        ),
    )
    df["bb_clone"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "clone -i " + str(x), True, "clone", "-i", str(x)
        ),
    )
    df["bb_export"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "export -i " + str(x), True, "export", "-i", str(x)
        ),
    )
    df["bb_start"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "start -i " + str(x), True, "start", "-i", str(x)
        ),
    )
    df["bb_stop"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "stop -i " + str(x), True, "stop", "-i", str(x)
        ),
    )
    df["bb_compress"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "compress -i " + str(x), True, "compress", "-i", str(x)
        ),
    )
    df["bb_isvmrunning"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess,
            "isvmrunning -i " + str(x),
            True,
            "isvmrunning",
            "-i",
            str(x),
        ),
    )
    df["bb_rename"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "rename -i " + str(x), True, "rename", "-i", str(x)
        ),
    )
    df["bb_taskstatus"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "taskstatus -i " + str(x), True, "taskstatus", "-i", str(x)
        ),
    )
    df["bb_randomize"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "randomize -i " + str(x), True, "randomize", "-i", str(x)
        ),
    )
    df["bb_execcmd"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "execcmd -i " + str(x), True, "execcmd", "-i", str(x)
        ),
    )
    df["bb_installapp"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "installapp -i " + str(x), True, "installapp", "-i", str(x)
        ),
    )
    df["bb_uninstallapp"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess,
            "uninstallapp -i " + str(x),
            True,
            "uninstallapp",
            "-i",
            str(x),
        ),
    )
    df["bb_startapp"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "startapp -i " + str(x), True, "startapp", "-i", str(x)
        ),
    )
    df["bb_stopapp"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "stopapp -i " + str(x), True, "stopapp", "-i", str(x)
        ),
    )
    df["bb_sendkey"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "sendkey -i " + str(x), True, "sendkey", "-i", str(x)
        ),
    )
    df["bb_activate"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "activate -i " + str(x), True, "activate", "-i", str(x)
        ),
    )
    df["bb_shake"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "shake -i " + str(x), True, "shake", "-i", str(x)
        ),
    )
    df["bb_rotate"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "rotate -i " + str(x), True, "rotate", "-i", str(x)
        ),
    )
    df["bb_reboot"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "reboot -i " + str(x), True, "reboot", "-i", str(x)
        ),
    )
    df["bb_connect"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "connect -i " + str(x), True, "connect", "-i", str(x)
        ),
    )
    df["bb_disconnect"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "disconnect -i " + str(x), True, "disconnect", "-i", str(x)
        ),
    )
    df["bb_input"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "input -i " + str(x), True, "input", "-i", str(x)
        ),
    )
    df["bb_setgps"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "setgps -i " + str(x), True, "setgps", "-i", str(x)
        ),
    )
    df["bb_setscreenlock"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess,
            "setscreenlock -i " + str(x),
            True,
            "setscreenlock",
            "-i",
            str(x),
        ),
    )
    df["bb_zoomin"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "zoomin -i " + str(x), True, "zoomin", "-i", str(x)
        ),
    )
    df["bb_zoomout"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "zoomout -i " + str(x), True, "zoomout", "-i", str(x)
        ),
    )
    df["bb_accelerometer"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess,
            "accelerometer -i " + str(x),
            True,
            "accelerometer",
            "-i",
            str(x),
        ),
    )
    df["bb_getappinfolist"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess,
            "getappinfolist -i " + str(x),
            True,
            "getappinfolist",
            "-i",
            str(x),
        ),
    )
    df["bb_createshortcut"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess,
            "createshortcut -i " + str(x),
            True,
            "createshortcut",
            "-i",
            str(x),
        ),
    )
    df["bb_network"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "network -i " + str(x), True, "network", "-i", str(x)
        ),
    )
    df["bb_uploadfile"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "uploadfile -i " + str(x), True, "uploadfile", "-i", str(x)
        ),
    )
    df["bb_downloadfile"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess,
            "downloadfile -i " + str(x),
            True,
            "downloadfile",
            "-i",
            str(x),
        ),
    )
    df["bb_createfile"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "createfile -i " + str(x), True, "createfile", "-i", str(x)
        ),
    )
    df["bb_removefile"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess, "removefile -i " + str(x), True, "removefile", "-i", str(x)
        ),
    )
    df["bb_adb"] = df.apply(
        lambda x: FlexiblePartialOwnName(
            run_subprocess,
            "adb -i " + str(x.aa_index),
            True,
            "adb",
            "-i",
            str(x.aa_index),
        )
        if "ERROR: " in x.aa_cpucap
        else pd.NA,
        axis=1,
    )
    df["bb_serial"] = df.apply(
        lambda x: ":".join(
            list(
                regex.findall(
                    r"([\d.]+):([\d.]+)",
                    x.bb_adb("get-serialno").stdout.decode("utf-8"),
                )[0]
            )
        )
        if "ERROR: " in x.aa_cpucap
        else pd.NA,
        axis=1,
    )
    df["bb_adbtools"] = df.ds_apply_ignore(
        pd.NA,
        lambda x: connect_adb_tools(x),
        axis=1,
    )

    df = pd.concat([df, df2], axis=1)
    ###############################################
    p = subprocess.run(
        [memumanage, "list", "-l", "vms"], capture_output=True
    ).stdout.decode("utf-8")
    dfa = [
        pd.DataFrame(
            [
                g if len(g := y.split(":", maxsplit=1)) > 1 else [y, ""]
                for y in x.splitlines()
                if not regex.match(r":\s*$", y.strip()) and ":" in y
            ]
        )
        for x in (regex.split(r"Name:[^\r\n']+[\r\n]+", p))
    ][1:]

    for ra in range(len(dfa)):
        dfa[ra][0] = dfa[ra][0].str.replace(r"\W+", "_", regex=True).str.strip("_")
        dfa[ra] = (
            dfa[ra]
            .set_axis(dfa[ra][0])
            .drop_duplicates(subset=0)
            .drop(columns=0)
            .assign(_1=lambda x: x[1].str.strip())
            .drop(columns=1)
            .rename(columns={"_1": 0})
            .T
        )
    dfallinfos = pd.concat(dfa, ignore_index=True)
    dfallinfos.columns = [f"cc_{x}" for x in dfallinfos.columns]
    newiond = []
    for acc in range(len(dfallinfos)):
        dfxax = pd.Q_Xml2df(
            dfallinfos.cc_Config_file.iloc[acc], add_xpath_and_snippet=False
        ).reset_index()
        try:
            nameindex = dfxax.loc[
                dfxax.aa_value.str.contains("name_tag", na=False)
            ].index[0]
        except Exception as fe:
            print(fe)
            continue
        nameacc = ""
        for key, item in dfxax[nameindex:].iterrows():
            if "value" in item["aa_all_keys"]:
                nameacc = item["aa_value"]
                newiond.append(str(nameacc))
                break

    dfallinfos["user_names"] = newiond
    dfallinfos = dfallinfos.sort_values(by="user_names").reset_index(drop=True)
    df = df.sort_values(by="aa_title").reset_index(drop=True)
    df = pd.concat([df, dfallinfos], axis=1, ignore_index=False)
    df = df.sort_values(by="aa_index").reset_index(drop=True)
    df["name_intern"] = (
        df["cc_Capture_file"]
        .str.split(os.sep, regex=False)
        .str[-1]
        .str.split(".", regex=False)
        .str[0]
    )
    ############################################
    df["controlvm_pause"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""""".rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "pause",
        ),
    )
    df["controlvm_resume"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""""".rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "resume",
        ),
    )
    df["controlvm_reset"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""""".rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "reset",
        ),
    )
    df["controlvm_poweroff"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""""".rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "poweroff",
        ),
    )
    df["controlvm_savestate"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""""".rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "savestate",
        ),
    )
    df["controlvm_acpipowerbutton"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""""".rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "acpipowerbutton",
        ),
    )
    df["controlvm_acpisleepbutton"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""""".rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "acpisleepbutton",
        ),
    )
    df["controlvm_keyboardputscancode"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<hex> [<hex> ...]| """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "keyboardputscancode",
        ),
    )
    df["controlvm_setlinkstate"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> on|off | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "setlinkstate",
        ),
    )
    df["controlvm_nic"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> null|nat|bridged|intnet|hostonly|generic|natnetwork [<devicename>] | """.rstrip(
                "| "
            ).lstrip(),
            True,
            "controlvm",
            str(x),
            "nic",
        ),
    )
    df["controlvm_nictrace"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> on|off | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "nictrace",
        ),
    )
    df["controlvm_nictracefile"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <filename> | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "nictracefile",
        ),
    )
    df["controlvm_nicproperty"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> name=[value] | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "nicproperty",
        ),
    )
    df["controlvm_nicpromisc"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> deny|allow-vms|allow-all | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "nicpromisc",
        ),
    )
    df["controlvm_natpf"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> [<rulename>],tcp|udp,[<hostip>],<hostport>,[<guestip>],<guestport> | """.rstrip(
                "| "
            ).lstrip(),
            True,
            "controlvm",
            str(x),
            "natpf",
        ),
    )
    df["controlvm_natpf"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> delete <rulename> | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "natpf",
        ),
    )
    df["controlvm_guestmemoryballoon"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<balloonsize in MB> | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "guestmemoryballoon",
        ),
    )
    df["controlvm_usbattach"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<uuid>|<address> [--capturefile <filename>] | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "usbattach",
        ),
    )
    df["controlvm_usbdetach"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<uuid>|<address> | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "usbdetach",
        ),
    )
    df["controlvm_clipboard"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""disabled|hosttoguest|guesttohost|bidirectional | """.rstrip(
                "| "
            ).lstrip(),
            True,
            "controlvm",
            str(x),
            "clipboard",
        ),
    )
    df["controlvm_draganddrop"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""disabled|hosttoguest | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "draganddrop",
        ),
    )
    df["controlvm_vrde"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "vrde",
        ),
    )
    df["controlvm_vrdeport"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<port> | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "vrdeport",
        ),
    )
    df["controlvm_vrdeproperty"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<name=[value]> | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "vrdeproperty",
        ),
    )
    df["controlvm_vrdevideochannelquality"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<percent> | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "vrdevideochannelquality",
        ),
    )
    df["controlvm_setvideomodehint"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<xres> <yres> <bpp> [[<display>] [<enabled:yes|no> |[<xorigin> <yorigin>]]] | """.rstrip(
                "| "
            ).lstrip(),
            True,
            "controlvm",
            str(x),
            "setvideomodehint",
        ),
    )
    df["controlvm_screenshotpng"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<file> [display] | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "screenshotpng",
        ),
    )
    df["controlvm_videocap"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "videocap",
        ),
    )
    df["controlvm_videocapscreens"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""all|none|<screen>,[<screen>...] | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "videocapscreens",
        ),
    )
    df["controlvm_videocapfile"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<file> """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "videocapfile",
        ),
    )
    df["controlvm_videocapres"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<width>x<height> """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "videocapres",
        ),
    )
    df["controlvm_videocaprate"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<rate> """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "videocaprate",
        ),
    )
    df["controlvm_videocapfps"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<fps> """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "videocapfps",
        ),
    )
    df["controlvm_videocapmaxtime"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<ms> """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "videocapmaxtime",
        ),
    )
    df["controlvm_videocapmaxsize"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<MB> """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "videocapmaxsize",
        ),
    )
    df["controlvm_setcredentials"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<username> --passwordfile <file> | <password> <domain> [--allowlocallogon <yes|no>] | """.rstrip(
                "| "
            ).lstrip(),
            True,
            "controlvm",
            str(x),
            "setcredentials",
        ),
    )
    df["controlvm_teleport"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""--host <name> --port <port> [--maxdowntime <msec>] [--passwordfile <file> |--password <password>] | """.rstrip(
                "| "
            ).lstrip(),
            True,
            "controlvm",
            str(x),
            "teleport",
        ),
    )
    df["controlvm_plugcpu"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<id> | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "plugcpu",
        ),
    )
    df["controlvm_unplugcpu"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<id> | """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "unplugcpu",
        ),
    )
    df["controlvm_cpuexecutioncap"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-100> """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "cpuexecutioncap",
        ),
    )
    df["controlvm_webcam"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<attach [path [settings]]> | <detach [path]> | <list> """.rstrip(
                "| "
            ).lstrip(),
            True,
            "controlvm",
            str(x),
            "webcam",
        ),
    )
    df["controlvm_addencpassword"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<id> <password file>|- [--removeonsuspend <yes|no>] """.rstrip(
                "| "
            ).lstrip(),
            True,
            "controlvm",
            str(x),
            "addencpassword",
        ),
    )
    df["controlvm_removeencpassword"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<id> """.rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "removeencpassword",
        ),
    )
    df["controlvm_removeallencpasswords"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""""".rstrip("| ").lstrip(),
            True,
            "controlvm",
            str(x),
            "removeallencpasswords",
        ),
    )
    ##################################################################
    df["modifyvm_name"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<name>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--name",
        ),
    )
    df["modifyvm_groups"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<group>, ...""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--groups",
        ),
    )
    df["modifyvm_description"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<desc>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--description",
        ),
    )
    df["modifyvm_ostype"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<ostype>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--ostype",
        ),
    )
    df["modifyvm_iconfile"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<filename>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--iconfile",
        ),
    )
    df["modifyvm_memory"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<memorysize in MB>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--memory",
        ),
    )
    df["modifyvm_pagefusion"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--pagefusion",
        ),
    )
    df["modifyvm_vram"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<vramsize in MB>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vram",
        ),
    )
    df["modifyvm_acpi"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--acpi",
        ),
    )
    df["modifyvm_pciattach"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""03:04.0""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--pciattach",
        ),
    )
    df["modifyvm_pciattach"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""03:04.0@02:01.0""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--pciattach",
        ),
    )
    df["modifyvm_pcidetach"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""03:04.0""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--pcidetach",
        ),
    )
    df["modifyvm_ioapic"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--ioapic",
        ),
    )
    df["modifyvm_hpet"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--hpet",
        ),
    )
    df["modifyvm_triplefaultreset"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--triplefaultreset",
        ),
    )
    df["modifyvm_apic"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--apic",
        ),
    )
    df["modifyvm_x2apic"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--x2apic",
        ),
    )
    df["modifyvm_paravirtprovider"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""none|default|legacy|minimal|hyperv|kvm""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--paravirtprovider",
        ),
    )
    df["modifyvm_paravirtdebug"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<key=value> [,<key=value> ...]""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--paravirtdebug",
        ),
    )
    df["modifyvm_hwvirtex"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--hwvirtex",
        ),
    )
    df["modifyvm_nestedpaging"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nestedpaging",
        ),
    )
    df["modifyvm_largepages"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--largepages",
        ),
    )
    df["modifyvm_vtxvpid"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vtxvpid",
        ),
    )
    df["modifyvm_vtxux"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vtxux",
        ),
    )
    df["modifyvm_pae"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--pae",
        ),
    )
    df["modifyvm_longmode"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--longmode",
        ),
    )
    df["modifyvm_ibpb-on-vm-exit"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--ibpb-on-vm-exit",
        ),
    )
    df["modifyvm_ibpb-on-vm-entry"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--ibpb-on-vm-entry",
        ),
    )
    df["modifyvm_cpu-profile"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f""""host|Intel 80[86|286|386]""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--cpu-profile",
        ),
    )
    df["modifyvm_cpuid-portability-level"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<0..3>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--cpuid-portability-level",
        ),
    )
    df["modifyvm_cpuidset"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<leaf> <eax> <ebx> <ecx> <edx>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--cpuidset",
        ),
    )
    df["modifyvm_cpuidremove"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<leaf>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--cpuidremove",
        ),
    )
    df["modifyvm_cpuidremoveall"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--cpuidremoveall",
        ),
    )
    df["modifyvm_hardwareuuid"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<uuid>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--hardwareuuid",
        ),
    )
    df["modifyvm_cpus"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<number>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--cpus",
        ),
    )
    df["modifyvm_cpuhotplug"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--cpuhotplug",
        ),
    )
    df["modifyvm_plugcpu"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<id>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--plugcpu",
        ),
    )
    df["modifyvm_unplugcpu"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<id>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--unplugcpu",
        ),
    )
    df["modifyvm_cpuexecutioncap"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-100>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--cpuexecutioncap",
        ),
    )
    df["modifyvm_rtcuseutc"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--rtcuseutc",
        ),
    )
    df["modifyvm_graphicscontroller"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""none|memuvga|vmsvga""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--graphicscontroller",
        ),
    )
    df["modifyvm_monitorcount"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<number>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--monitorcount",
        ),
    )
    df["modifyvm_accelerate3d"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--accelerate3d",
        ),
    )
    df["modifyvm_accelerate2dvideo"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--accelerate2dvideo",
        ),
    )
    df["modifyvm_firmware"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""bios|efi|efi32|efi64""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--firmware",
        ),
    )
    df["modifyvm_chipset"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""ich9|piix3""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--chipset",
        ),
    )
    df["modifyvm_bioslogofadein"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--bioslogofadein",
        ),
    )
    df["modifyvm_bioslogofadeout"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--bioslogofadeout",
        ),
    )
    df["modifyvm_bioslogodisplaytime"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<msec>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--bioslogodisplaytime",
        ),
    )
    df["modifyvm_bioslogoimagepath"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<imagepath>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--bioslogoimagepath",
        ),
    )
    df["modifyvm_biosbootmenu"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""disabled|menuonly|messageandmenu""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--biosbootmenu",
        ),
    )
    df["modifyvm_biosapic"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""disabled|apic|x2apic""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--biosapic",
        ),
    )
    df["modifyvm_biossystemtimeoffset"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<msec>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--biossystemtimeoffset",
        ),
    )
    df["modifyvm_biospxedebug"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--biospxedebug",
        ),
    )
    df["modifyvm_boot"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-4> none|floppy|dvd|disk|net>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--boot",
        ),
    )
    df["modifyvm_nic"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> none|null|nat|bridged|intnet|hostonly|generic|natnetwork""".rstrip(
                "| "
            ),
            True,
            "modifyvm",
            str(x),
            "--nic",
        ),
    )
    df["modifyvm_nictype"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> Am79C970A|Am79C973|82540EM|82543GC|82545EM|virtio""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nictype",
        ),
    )
    df["modifyvm_cableconnected"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--cableconnected",
        ),
    )
    df["modifyvm_nictrace"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nictrace",
        ),
    )
    df["modifyvm_nictracefile"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <filename>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nictracefile",
        ),
    )
    df["modifyvm_nicproperty"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> name=[value]""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nicproperty",
        ),
    )
    df["modifyvm_nicspeed"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <kbps>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nicspeed",
        ),
    )
    df["modifyvm_nicbootprio"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <priority>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nicbootprio",
        ),
    )
    df["modifyvm_nicpromisc"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> deny|allow-vms|allow-all""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nicpromisc",
        ),
    )
    df["modifyvm_nicbandwidthgroup"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> none|<name>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nicbandwidthgroup",
        ),
    )
    df["modifyvm_bridgeadapter"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> none|<devicename>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--bridgeadapter",
        ),
    )
    df["modifyvm_hostonlyadapter"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> none|<devicename>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--hostonlyadapter",
        ),
    )
    df["modifyvm_intnet"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <network name>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--intnet",
        ),
    )
    df["modifyvm_nat-network"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <network name>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nat-network",
        ),
    )
    df["modifyvm_nicgenericdrv"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <driver>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nicgenericdrv",
        ),
    )
    df["modifyvm_natnet"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <network>|default""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--natnet",
        ),
    )
    df["modifyvm_natsettings"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> [<mtu>],[<socksnd>][<sockrcv>],[<tcpsnd>],[<tcprcv>]""".rstrip(
                "| "
            ),
            True,
            "modifyvm",
            str(x),
            "--natsettings",
        ),
    )
    df["modifyvm_natpf"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> [<rulename>],tcp|udp,[<hostip>], <hostport>,[<guestip>],<guestport>""".rstrip(
                "| "
            ),
            True,
            "modifyvm",
            str(x),
            "--natpf",
        ),
    )
    df["modifyvm_natpf"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> delete <rulename>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--natpf",
        ),
    )
    df["modifyvm_nattftpprefix"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <prefix>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nattftpprefix",
        ),
    )
    df["modifyvm_nattftpfile"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <file>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nattftpfile",
        ),
    )
    df["modifyvm_nattftpserver"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <ip>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nattftpserver",
        ),
    )
    df["modifyvm_natbindip"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> <ip>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--natbindip",
        ),
    )
    df["modifyvm_natdnspassdomain"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--natdnspassdomain",
        ),
    )
    df["modifyvm_natdnsproxy"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--natdnsproxy",
        ),
    )
    df["modifyvm_natdnshostresolver"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--natdnshostresolver",
        ),
    )
    df["modifyvm_nataliasmode"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> default|[log],[proxyonly],[sameports]""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--nataliasmode",
        ),
    )
    df["modifyvm_macaddress"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage_n,
            f"""<1-N> auto|<mac>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--macaddress",
        ),
    )
    # df["modifyvm_macaddress2"] = df["name_intern"].ds_apply_ignore(
    #     pd.NA,
    #     lambda x: FlexiblePartialOwnName(
    #         run_subprocess_manage,
    #         f"""<1-N> auto|<mac>""".rstrip("| "),
    #         True,
    #         "modifyvm",
    #         str(x),
    #         "--macaddress2",
    #     ),
    # )

    df["modifyvm_mouse"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""ps2|usb|usbtablet|usbmultitouch""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--mouse",
        ),
    )
    df["modifyvm_keyboard"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""ps2|usb""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--keyboard",
        ),
    )
    df["modifyvm_uart"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<1-N> off|<I/O base> <IRQ>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--uart",
        ),
    )
    df["modifyvm_uartmode"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<1-N> disconnected|server <pipe>|client <pipe>|tcpserver <port>|tcpclient <hostname:port>|file <file>|<devicename>""".rstrip(
                "| "
            ),
            True,
            "modifyvm",
            str(x),
            "--uartmode",
        ),
    )
    df["modifyvm_lpt"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<1-N> off|<I/O base> <IRQ>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--lpt",
        ),
    )
    df["modifyvm_lptmode"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<1-N> <devicename>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--lptmode",
        ),
    )
    df["modifyvm_guestmemoryballoon"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<balloonsize in MB>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--guestmemoryballoon",
        ),
    )
    df["modifyvm_audio"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""none|null|dsound""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--audio",
        ),
    )
    df["modifyvm_audiocontroller"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""ac97|hda|sb16""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--audiocontroller",
        ),
    )
    df["modifyvm_audiocodec"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""stac9700|ad1980|stac9221|sb16""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--audiocodec",
        ),
    )
    df["modifyvm_clipboard"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""disabled|hosttoguest|guesttohost|bidirectional""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--clipboard",
        ),
    )
    df["modifyvm_draganddrop"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""disabled|hosttoguest""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--draganddrop",
        ),
    )
    df["modifyvm_vrde"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrde",
        ),
    )
    df["modifyvm_vrdeextpack"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""default|<name>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdeextpack",
        ),
    )
    df["modifyvm_vrdeproperty"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<name=[value]>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdeproperty",
        ),
    )
    df["modifyvm_vrdeport"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<hostport>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdeport",
        ),
    )
    df["modifyvm_vrdeaddress"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<hostip>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdeaddress",
        ),
    )
    df["modifyvm_vrdeauthtype"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""null|external|guest""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdeauthtype",
        ),
    )
    df["modifyvm_vrdeauthlibrary"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""default|<name>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdeauthlibrary",
        ),
    )
    df["modifyvm_vrdemulticon"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdemulticon",
        ),
    )
    df["modifyvm_vrdereusecon"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdereusecon",
        ),
    )
    df["modifyvm_vrdevideochannel"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdevideochannel",
        ),
    )
    df["modifyvm_vrdevideochannelquality"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<percent>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--vrdevideochannelquality",
        ),
    )
    df["modifyvm_usb"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--usb",
        ),
    )
    df["modifyvm_usbehci"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--usbehci",
        ),
    )
    df["modifyvm_usbxhci"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--usbxhci",
        ),
    )
    df["modifyvm_usbrename"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<oldname> <newname>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--usbrename",
        ),
    )
    df["modifyvm_snapshotfolder"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""default|<path>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--snapshotfolder",
        ),
    )
    df["modifyvm_teleporter"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--teleporter",
        ),
    )
    df["modifyvm_teleporterport"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<port>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--teleporterport",
        ),
    )
    df["modifyvm_teleporteraddress"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<address|empty>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--teleporteraddress",
        ),
    )
    df["modifyvm_teleporterpassword"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<password>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--teleporterpassword",
        ),
    )
    df["modifyvm_teleporterpasswordfile"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<file>|stdin""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--teleporterpasswordfile",
        ),
    )
    df["modifyvm_tracing-enabled"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--tracing-enabled",
        ),
    )
    df["modifyvm_tracing-config"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<config-string>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--tracing-config",
        ),
    )
    df["modifyvm_tracing-allow-vm-access"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--tracing-allow-vm-access",
        ),
    )
    df["modifyvm_usbcardreader"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--usbcardreader",
        ),
    )
    df["modifyvm_autostart-enabled"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""on|off""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--autostart-enabled",
        ),
    )
    df["modifyvm_autostart-delay"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""<seconds>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--autostart-delay",
        ),
    )
    df["modifyvm_defaultfrontend"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            f"""default|<name>""".rstrip("| "),
            True,
            "modifyvm",
            str(x),
            "--defaultfrontend",
        ),
    )
    ########################################
    df["startvm_gui"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            "gui",
            True,
            "startvm",
            str(x),
            "--type",
            "gui",
        ),
    )
    df["startvm_sdl"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            "sdl",
            True,
            "startvm",
            str(x),
            "--type",
            "sdl",
        ),
    )
    df["startvm_headless"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            "headless",
            True,
            "startvm",
            str(x),
            "--type",
            "headless",
        ),
    )
    df["startvm_separate"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            "separate",
            True,
            "startvm",
            str(x),
            "--type",
            "separate",
        ),
    )
    ########################################
    df["guestcontrol_run"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[--exe <path to executable>] [--timeout <msec>] [-E|--putenv <NAME>[=<VALUE>]] [--unquoted-args] [--ignore-operhaned-processes] [--profile] [--no-wait-stdout|--wait-stdout] [--no-wait-stderr|--wait-stderr] [--dos2unix] [--unix2dos] -- <program/arg0> [argument1] ... [argumentN]]""",
            True,
            "guestcontrol",
            str(x),
            "run",
        ),
    )
    df["guestcontrol_start"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[--exe <path to executable>] [--timeout <msec>] [-E|--putenv <NAME>[=<VALUE>]] [--unquoted-args] [--ignore-operhaned-processes] [--profile]  <program/arg0> [argument1] ... [argumentN]]""",
            True,
            "guestcontrol",
            str(x),
            "start",
        ),
    )
    df["guestcontrol_copyfrom"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[--dryrun] [--follow] [-R|--recursive] <guest-src0> [guest-src1 [...]] <host-dst>""",
            True,
            "guestcontrol",
            str(x),
            "copyfrom",
        ),
    )
    df["guestcontrol_copyto"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[--dryrun] [--follow] [-R|--recursive] <host-src0> [host-src1 [...]] <guest-dst>""",
            True,
            "guestcontrol",
            str(x),
            "copyto",
        ),
    )
    df["guestcontrol_mkdir"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[--parents] [--mode <mode>] <guest directory> [...]""",
            True,
            "guestcontrol",
            str(x),
            "mkdir",
        ),
    )
    df["guestcontrol_rmdir"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[-R|--recursive] <guest directory> [...]""",
            True,
            "guestcontrol",
            str(x),
            "rmdir",
        ),
    )
    df["guestcontrol_rm"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[-f|--force] <guest file> [...]""",
            True,
            "guestcontrol",
            str(x),
            "rm",
        ),
    )
    df["guestcontrol_move"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """<source> [source1 [...]] <dest>""",
            True,
            "guestcontrol",
            str(x),
            "move",
        ),
    )
    df["guestcontrol_mktemp"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[--secure] [--mode <mode>] [--tmpdir <directory>] <template>""",
            True,
            "guestcontrol",
            str(x),
            "mktemp",
        ),
    )
    df["guestcontrol_stat"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """<file> [...]""",
            True,
            "guestcontrol",
            str(x),
            "stat",
        ),
    )
    df["guestcontrol_list"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """<all|sessions|processes|files> [common-opts]""",
            True,
            "guestcontrol",
            str(x),
            "list",
        ),
    )
    df["guestcontrol_closeprocess"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """<   --session-id <ID> | --session-name <name or pattern> <PID1> [PID1 [...]]""",
            True,
            "guestcontrol",
            str(x),
            "closeprocess",
        ),
    )
    df["guestcontrol_closesession"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[common-options] <  --all | --session-id <ID>  | --session-name <name or pattern> >""",
            True,
            "guestcontrol",
            str(x),
            "closesession",
        ),
    )
    df["guestcontrol_updateadditions"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """[--source <guest additions .ISO>] [--wait-start] [common-options] [-- [<argument1>] ... [<argumentN>]]""",
            True,
            "guestcontrol",
            str(x),
            "updateadditions",
        ),
    )
    df["guestcontrol_watch"] = df["name_intern"].ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            run_subprocess_manage,
            """""",
            True,
            "guestcontrol",
            str(x),
            "watch",
        ),
    )
    ########################################
    df.columns = [str(x).replace("-", "_").rstrip("_") for x in df.columns]
    df = df.sort_values(by="aa_index").reset_index(drop=True)
    hddisks = [("uuid_" + x[3:], x) for x in df.columns if "IDE" in x]
    for col, col2 in hddisks:
        df[col] = df[col2].str.split("UUID:").str[-1].str.strip(" )")
    for col2, col1 in hddisks:
        col1 = col1[3:]
        df[f"modifymedium_type_{col1}"] = df[col2].ds_apply_ignore(
            pd.NA,
            lambda x: FlexiblePartialOwnName(
                run_subprocess_manage,
                """normal|writethrough|immutable|shareable|readonly|multiattach""",
                True,
                "modifymedium",
                str(x),
                "--type",
            ),
        )
        df[f"modifymedium_autoreset_{col1}"] = df[col2].ds_apply_ignore(
            pd.NA,
            lambda x: FlexiblePartialOwnName(
                run_subprocess_manage,
                """on|off""",
                True,
                "modifymedium",
                str(x),
                "--autoreset",
            ),
        )
        df[f"modifymedium_property_{col1}"] = df[col2].ds_apply_ignore(
            pd.NA,
            lambda x: FlexiblePartialOwnName(
                run_subprocess_manage,
                """<name=[value>]""",
                True,
                "modifymedium",
                str(x),
                "--property",
            ),
        )
        df[f"modifymedium_compac_{col1}"] = df[col2].ds_apply_ignore(
            pd.NA,
            lambda x: FlexiblePartialOwnName(
                run_subprocess_manage,
                """""",
                True,
                "modifymedium",
                str(x),
                "--compact",
            ),
        )
        df[f"modifymedium_resize_{col1}"] = df[col2].ds_apply_ignore(
            pd.NA,
            lambda x: FlexiblePartialOwnName(
                run_subprocess_manage,
                """<megabytes>""",
                True,
                "modifymedium",
                str(x),
                "--resize",
            ),
        )
        df[f"modifymedium_resizebyte_{col1}"] = df[col2].ds_apply_ignore(
            pd.NA,
            lambda x: FlexiblePartialOwnName(
                run_subprocess_manage,
                """<bytes>""",
                True,
                "modifymedium",
                str(x),
                "--resizebyte",
            ),
        )
        df[f"modifymedium_move_{col1}"] = df[col2].ds_apply_ignore(
            pd.NA,
            lambda x: FlexiblePartialOwnName(
                run_subprocess_manage,
                """<path>""",
                True,
                "modifymedium",
                str(x),
                "--move",
            ),
        )
    df["bb_input_natural"] = df.aa_index.ds_apply_ignore(
        pd.NA,
        lambda x: FlexiblePartialOwnName(
            natural_input, "input -i " + str(x), False, 0.1, 0.3, indi=str(x)
        ),
    )
    return df


def natural_input(text, s=0.1, e=0.3, *args, **kwargs):
    for letra in text:
        p = run_subprocess("input", "-i", kwargs["indi"], str(letra))
        sleep(random.uniform(s, e))


class DfDescriptor:
    def __get__(self, instance, owner):
        return instance.df[self.name]

    def __set__(self, instance, value):
        instance.__dict__[self.name] = instance.df[self.name]

    def __delete__(self, instance):
        instance.__dict__["df"] = instance.df.drop(self.name)

    def __set_name__(self, owner, name):
        self.name = name


class MeMuc:
    aa_index = DfDescriptor()
    aa_title = DfDescriptor()
    aa_handle = DfDescriptor()
    aa_status = DfDescriptor()
    aa_pid = DfDescriptor()
    aa_cpus = DfDescriptor()
    aa_memory = DfDescriptor()
    aa_cpucap = DfDescriptor()
    aa_picturepath = DfDescriptor()
    aa_musicpath = DfDescriptor()
    aa_moviepath = DfDescriptor()
    aa_downloadpath = DfDescriptor()
    aa_is_full_screen = DfDescriptor()
    aa_is_hide_toolbar = DfDescriptor()
    aa_graphics_render_mode = DfDescriptor()
    aa_enable_su = DfDescriptor()
    aa_enable_audio = DfDescriptor()
    aa_fps = DfDescriptor()
    aa_vkeyboard_mode = DfDescriptor()
    aa_sync_time = DfDescriptor()
    aa_phone_layout = DfDescriptor()
    aa_start_window_mode = DfDescriptor()
    aa_win_x = DfDescriptor()
    aa_win_y = DfDescriptor()
    aa_win_scaling_percent2 = DfDescriptor()
    aa_resolution_width = DfDescriptor()
    aa_resolution_height = DfDescriptor()
    aa_vbox_dpi = DfDescriptor()
    aa_linenum = DfDescriptor()
    aa_imei = DfDescriptor()
    aa_imsi = DfDescriptor()
    aa_simserial = DfDescriptor()
    aa_microvirt_vm_brand = DfDescriptor()
    aa_microvirt_vm_manufacturer = DfDescriptor()
    aa_microvirt_vm_model = DfDescriptor()
    aa_selected_map = DfDescriptor()
    aa_longitude = DfDescriptor()
    aa_latitude = DfDescriptor()
    bb_remove = DfDescriptor()
    bb_clone = DfDescriptor()
    bb_export = DfDescriptor()
    bb_start = DfDescriptor()
    bb_stop = DfDescriptor()
    bb_compress = DfDescriptor()
    bb_isvmrunning = DfDescriptor()
    bb_rename = DfDescriptor()
    bb_taskstatus = DfDescriptor()
    bb_randomize = DfDescriptor()
    bb_execcmd = DfDescriptor()
    bb_installapp = DfDescriptor()
    bb_uninstallapp = DfDescriptor()
    bb_startapp = DfDescriptor()
    bb_stopapp = DfDescriptor()
    bb_sendkey = DfDescriptor()
    bb_activate = DfDescriptor()
    bb_shake = DfDescriptor()
    bb_rotate = DfDescriptor()
    bb_reboot = DfDescriptor()
    bb_connect = DfDescriptor()
    bb_disconnect = DfDescriptor()
    bb_input = DfDescriptor()
    bb_setgps = DfDescriptor()
    bb_setscreenlock = DfDescriptor()
    bb_zoomin = DfDescriptor()
    bb_zoomout = DfDescriptor()
    bb_accelerometer = DfDescriptor()
    bb_getappinfolist = DfDescriptor()
    bb_createshortcut = DfDescriptor()
    bb_network = DfDescriptor()
    bb_uploadfile = DfDescriptor()
    bb_downloadfile = DfDescriptor()
    bb_createfile = DfDescriptor()
    bb_removefile = DfDescriptor()
    bb_adb = DfDescriptor()
    bb_serial = DfDescriptor()
    bb_adbtools = DfDescriptor()
    set_index = DfDescriptor()
    set_cpus = DfDescriptor()
    set_memory = DfDescriptor()
    set_picturepath = DfDescriptor()
    set_musicpath = DfDescriptor()
    set_moviepath = DfDescriptor()
    set_downloadpath = DfDescriptor()
    set_graphics_render_mode = DfDescriptor()
    set_enable_su = DfDescriptor()
    set_enable_audio = DfDescriptor()
    set_fps = DfDescriptor()
    set_vkeyboard_mode = DfDescriptor()
    set_sync_time = DfDescriptor()
    set_phone_layout = DfDescriptor()
    set_start_window_mode = DfDescriptor()
    set_win_x = DfDescriptor()
    set_win_y = DfDescriptor()
    set_win_scaling_percent2 = DfDescriptor()
    set_resolution_width = DfDescriptor()
    set_resolution_height = DfDescriptor()
    set_vbox_dpi = DfDescriptor()
    set_linenum = DfDescriptor()
    set_imei = DfDescriptor()
    set_imsi = DfDescriptor()
    set_simserial = DfDescriptor()
    set_microvirt_vm_brand = DfDescriptor()
    set_microvirt_vm_manufacturer = DfDescriptor()
    set_microvirt_vm_model = DfDescriptor()
    set_selected_map = DfDescriptor()
    set_longitude = DfDescriptor()
    set_latitude = DfDescriptor()

    def __init__(self):
        self.df = get_all_config(list_all_emulators())
        self.df = self.df.drop(
            columns=[
                "set_pid",
                "set_status",
                "set_handle",
                "set_title",
                "set_index",
                "set_cpucap",
                "set_is_full_screen",
                "set_is_hide_toolbar",
            ]
        )

        self.aa_index = None
        self.aa_title = None
        self.aa_handle = None
        self.aa_status = None
        self.aa_pid = None
        self.aa_cpus = None
        self.aa_memory = None
        self.aa_cpucap = None
        self.aa_picturepath = None
        self.aa_musicpath = None
        self.aa_moviepath = None
        self.aa_downloadpath = None
        self.aa_is_full_screen = None
        self.aa_is_hide_toolbar = None
        self.aa_graphics_render_mode = None
        self.aa_enable_su = None
        self.aa_enable_audio = None
        self.aa_fps = None
        self.aa_vkeyboard_mode = None
        self.aa_sync_time = None
        self.aa_phone_layout = None
        self.aa_start_window_mode = None
        self.aa_win_x = None
        self.aa_win_y = None
        self.aa_win_scaling_percent2 = None
        self.aa_resolution_width = None
        self.aa_resolution_height = None
        self.aa_vbox_dpi = None
        self.aa_linenum = None
        self.aa_imei = None
        self.aa_imsi = None
        self.aa_simserial = None
        self.aa_microvirt_vm_brand = None
        self.aa_microvirt_vm_manufacturer = None
        self.aa_microvirt_vm_model = None
        self.aa_selected_map = None
        self.aa_longitude = None
        self.aa_latitude = None
        self.bb_remove = None
        self.bb_clone = None
        self.bb_export = None
        self.bb_start = None
        self.bb_stop = None
        self.bb_compress = None
        self.bb_isvmrunning = None
        self.bb_rename = None
        self.bb_taskstatus = None
        self.bb_randomize = None
        self.bb_execcmd = None
        self.bb_installapp = None
        self.bb_uninstallapp = None
        self.bb_startapp = None
        self.bb_stopapp = None
        self.bb_sendkey = None
        self.bb_activate = None
        self.bb_shake = None
        self.bb_rotate = None
        self.bb_reboot = None
        self.bb_connect = None
        self.bb_disconnect = None
        self.bb_input = None
        self.bb_setgps = None
        self.bb_setscreenlock = None
        self.bb_zoomin = None
        self.bb_zoomout = None
        self.bb_accelerometer = None
        self.bb_getappinfolist = None
        self.bb_createshortcut = None
        self.bb_network = None
        self.bb_uploadfile = None
        self.bb_downloadfile = None
        self.bb_createfile = None
        self.bb_removefile = None
        self.bb_adb = None
        self.bb_serial = None
        self.bb_adbtools = None
        self.set_cpus = None
        self.set_memory = None
        self.set_picturepath = None
        self.set_musicpath = None
        self.set_moviepath = None
        self.set_downloadpath = None
        self.set_graphics_render_mode = None
        self.set_enable_su = None
        self.set_enable_audio = None
        self.set_fps = None
        self.set_vkeyboard_mode = None
        self.set_sync_time = None
        self.set_phone_layout = None
        self.set_start_window_mode = None
        self.set_win_x = None
        self.set_win_y = None
        self.set_win_scaling_percent2 = None
        self.set_resolution_width = None
        self.set_resolution_height = None
        self.set_vbox_dpi = None
        self.set_linenum = None
        self.set_imei = None
        self.set_imsi = None
        self.set_simserial = None
        self.set_microvirt_vm_brand = None
        self.set_microvirt_vm_manufacturer = None
        self.set_microvirt_vm_model = None
        self.set_selected_map = None
        self.set_longitude = None
        self.set_latitude = None

    def _create_vm(self, v="96", timeout=30):
        subprocess_timeout(
            [memuc, "create", v],
            shell=False,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )

        self.df = get_all_config(list_all_emulators())

    def __str__(self):
        print(self.df)
        return ""

    def __repr__(self):
        print(self.df)
        return ""

    def __missing__(self, key):
        return getattr(self.df, key)

    def __getitem__(self, item):
        return self.df[item]

    def __getattr__(self, item):
        try:
            return getattr(self, item)
        except Exception:
            return getattr(self.df, item)

    def import_vm(self, path, name):
        activeones = self.df.aa_title.to_list()
        if name in activeones:
            raise ValueError("Name does already exist!")
        p = subprocess.run(
            [memuc, "import", os.path.normpath(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.df = get_all_config(list_all_emulators())
        self.df = self.df.loc[~self.df.aa_title.isin(activeones)]
        self.df.iloc[0].set_enable_su(1)
        self.df.bb_randomize.iloc[0]()
        p = subprocess.run(
            [memuc, "rename", "-i", str(self.df.aa_index.iloc[-1]), name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.change_config(0)
        return self

    def patch_hosts(
        self,
        vms_aa_index,
        hostfiles=(
            "https://adaway.org/hosts.txt",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
            "https://winhelp2002.mvps.org/hosts.txt",
        ),
    ):
        hostfile = get_hosts_files(allhosts=hostfiles)

        if not isiter(vms_aa_index):
            vms_aa_index = [vms_aa_index]
        df2 = self.df.loc[self.df.aa_index.isin(vms_aa_index)]
        suenabled = df2.loc[df2.aa_enable_su == "1"]
        sudisabled = df2.loc[df2.aa_enable_su == "0"]
        for key, item in suenabled.iterrows():
            aa_index = item.aa_index
            item.bb_start()
            sleep(3)

            self2 = pd.DataFrame()
            while self2.empty:
                self23 = self.__class__()
                self2 = self23.loc[self23.aa_index == aa_index]
                if pd.isna(self2.iloc[0].bb_adbtools):
                    self2 = pd.DataFrame()
            self2.iloc[0].bb_adbtools.aa_execute_non_shell_adb_command("remount")
            self2.iloc[0].bb_adbtools.aa_enable_root()
            self2.iloc[0].bb_adbtools.aa_execute_multiple_adb_shell_commands(
                ["rm ./etc/hosts"]
            )
            self2.iloc[0].bb_adbtools.aa_push_file_to_path(hostfile, "./etc")
            print(
                f"len of host file: {len(self2.iloc[0].bb_adbtools.aa_execute_multiple_adb_shell_commands(['cat ./etc/hosts']))}"
            )
            item.bb_stop()

        for key, item in sudisabled.iterrows():
            aa_index = item.aa_index
            for ita in range(2):
                item.bb_stop()
                item.set_enable_su(1)
                item.bb_start()
                sleep(3)
                self2 = pd.DataFrame()
                while self2.empty:
                    self23 = self.__class__()
                    self2 = self23.loc[self23.aa_index == aa_index]
                    if pd.isna(self2.iloc[0].bb_adbtools):
                        self2 = pd.DataFrame()
                self2.iloc[0].bb_adbtools.aa_execute_non_shell_adb_command("remount")
                self2.iloc[0].bb_adbtools.aa_enable_root()
                self2.iloc[0].bb_adbtools.aa_execute_multiple_adb_shell_commands(
                    ["rm ./etc/hosts"]
                )
                self2.iloc[0].bb_adbtools.aa_push_file_to_path(hostfile, "./etc")
                if ita ==1:
                    print(
                        f"len of host file: {len(self2.iloc[0].bb_adbtools.aa_execute_multiple_adb_shell_commands(['cat ./etc/hosts']))}"
                    )
                    self2.iloc[0].set_enable_su(0)
                item.bb_stop()

        try:
            os.remove(hostfile)

        except Exception:
            pass
        self.update_status()
        return self
    def change_config(self, i):
        self.df.iloc[i].set_enable_audio(0)
        try:
            sa = phoneconfig.phone_dataframe.sample(1)

            self.df.iloc[i].set_linenum(sa.phone_number.iloc[0])
            self.df.iloc[i].set_imei(sa.imei.iloc[0])
            self.df.iloc[i].set_imsi(sa.cc_imsi.iloc[0])
            self.df.iloc[i].set_simserial(sa.cc_simerial.iloc[0])
        except Exception:
            pass

        self.df.modifyvm_macaddress.iloc[0](
            1,
            (
                str(phoneconfig.mac_address_prefix)
                + ":%02x:%02x:%02x" % tuple(random.randint(0, 255) for v in range(3))
            ).replace(":", ""),
        )

        self.df.modifyvm_macaddress.iloc[0](
            2,
            (
                str(phoneconfig.mac_address_prefix)
                + ":%02x:%02x:%02x" % tuple(random.randint(0, 255) for v in range(3))
            ).replace(":", ""),
        )
        self.df.iloc[i].set_enable_su(0)

        self.df = get_all_config(list_all_emulators())
        return self

    def update_status(self):
        self.df = get_all_config(list_all_emulators())
        return self

    def create_vm_44(self, timeout=120):
        self._create_vm(v="44", timeout=timeout)
        return self

    def create_vm_51(self, timeout=120):
        self._create_vm(v="51", timeout=timeout)
        return self

    def create_vm_71(self, timeout=120):
        self._create_vm(v="71", timeout=timeout)
        return self

    def create_vm_76(self, timeout=120):
        self._create_vm(v="76", timeout=timeout)
        return self

    def create_vm_90(self, timeout=120):
        self._create_vm(v="90", timeout=timeout)
        return self

    def create_vm_96(self, timeout=120):
        self._create_vm(v="96", timeout=timeout)
        return self

    def get_ui_automator_df(
        self,
        i,
        screenshotfolder=None,
        save_screenshot=False,
        max_variation_percent_x=10,
        max_variation_percent_y=10,
        loung_touch_delay=(
            1000,
            1500,
        ),
        swipe_variation_startx=10,
        swipe_variation_endx=10,
        swipe_variation_starty=10,
        swipe_variation_endy=10,
        sdcard="/storage/emulated/0/",
        tmp_folder_on_sd_card="AUTOMAT",
        bluestacks_divider=32767,
    ):
        df2 = self.df.loc[self.df.aa_index == i]
        try:
            df2.bb_adbtools.iloc[0].aa_update_screenshot()
        except Exception:
            print("Could not get screenshot")
            save_screenshot = False
            screenshotfolder = None
        df3 = df2.bb_adbtools.iloc[0].aa_get_all_displayed_items_from_uiautomator(
            screenshotfolder=screenshotfolder,
            max_variation_percent_x=max_variation_percent_x,
            max_variation_percent_y=max_variation_percent_y,
            loung_touch_delay=loung_touch_delay,
            swipe_variation_startx=swipe_variation_startx,
            swipe_variation_endx=swipe_variation_endx,
            swipe_variation_starty=swipe_variation_starty,
            swipe_variation_endy=swipe_variation_endy,
            sdcard=sdcard,
            tmp_folder_on_sd_card=tmp_folder_on_sd_card,
            bluestacks_divider=bluestacks_divider,
        )
        if save_screenshot:
            df3.dropna(subset="bb_screenshot").ff_bb_save_screenshot.apply(
                lambda x: x()
            )
        return df3
