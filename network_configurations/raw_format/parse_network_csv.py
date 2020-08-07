import json
import pandas as pd
import random


# TODO is this file needed?
def parse_network_csv(filename):
    output_network = {"clients": {}, "routers": {}, "servers": {}, "firewalls": {}}
    with open("linux_mapping.json") as mapping_f:
        linux_map = json.load(mapping_f)

    with open("../cves/vendors_products.json") as vp_f:
        vp = json.load(vp_f)

    x1 = pd.ExcelFile(filename)
    df = x1.parse("Nodes")
    for index, row in df.iterrows():
        if not (pd.isnull(row["Role"]) or pd.isnull(row["OS"])):
            role = row["Role"].replace(",type:", "_")
            os = row["OS"]
            id = row["Node ID"]
            all_cpes = None
            if "linux" in os or "Sophos" in os:
                all_cpes = {"os": linux_map[os]}
                all_cpes.update(get_applications("linux"))

            else:
                microsoft = vp["microsoft"]
                split_os = os.split(" ")
                for app_name in microsoft.keys():
                    if split_os[0] in app_name and split_os[1] in app_name:
                        all_cpes = {"os": microsoft[app_name]}
                        all_cpes.update(get_applications("microsoft"))
                        break

            if all_cpes is None:
                print(role, os)
            else:
                if "client" in role:
                    if role in output_network["clients"]:
                        output_network["clients"][role][id] = all_cpes
                    else:
                        output_network["clients"][role] = {id: all_cpes}
                elif "router" in role:
                    if role in output_network["routers"]:
                        output_network["routers"][role][id] = all_cpes
                    else:
                        output_network["routers"][role] = {id: all_cpes}
                elif "server" in role:
                    if role in output_network["servers"]:
                        output_network["servers"][role][id] = all_cpes
                    else:
                        output_network["servers"][role] = {id: all_cpes}
                elif "firewall" in role:
                    if role in output_network["firewalls"]:
                        output_network["firewalls"][role][id] = all_cpes
                    else:
                        output_network["firewalls"][role] = {id: all_cpes}
                else:
                    print(role, os, all_cpes)

    return output_network


def get_applications(os):
    with open("os_applications.json") as os_app_f:
        os_apps = json.load(os_app_f)

    app_lists = None
    if os == "microsoft":
        app_lists = os_apps["microsoft"]
    elif os == "linux":
        app_lists = os_apps["linux"]

    output_apps = {}
    count = 0
    for app_type in app_lists:
        partial = {}
        for application in app_lists[app_type]:
            if random.random() < 1 / 3:
                partial["app" + str(count)] = application
                count += 1
        if len(partial) == 0:
            choice = random.choice(app_lists[app_type])
            partial["app" + str(count)] = choice
            count += 1
        output_apps.update(partial)
    return output_apps


network = parse_network_csv("network2.xlsx")
# print(get_applications("microsoft"))
with open("network_config_small2.0.json", "w") as net_f:
    net_f.write(json.dumps(network, indent=4, sort_keys=True))
