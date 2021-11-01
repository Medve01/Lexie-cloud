import subprocess


def pc_query(custom_data): # pylint: disable=unused-argument
    """[summary]

    Args:
        custom_data ([type]): [description]

    Returns:
        [type]: [description]
    """
    p = subprocess.run(["ping", "-c", "1", "192.168.0.2"], stdout=subprocess.PIPE) # pylint: disable=subprocess-run-check
    state = p.returncode == 0
    return {"on": state, "online": True}

def pc_action(custom_data, command, params): # pylint: disable=unused-argument
    """[summary]

    Args:
        custom_data ([type]): [description]
        command ([type]): [description]
        params ([type]): [description]

    Returns:
        [type]: [description]
    """
    if command == "action.devices.commands.OnOff":
        if params['on']:
            subprocess.run(["wakeonlan", "-i", "192.168.0.255", "00:11:22:33:44:55"]) # pylint: disable=subprocess-run-check
        else:
            subprocess.run(["sh", "-c", "echo shutdown -h | ssh clust@192.168.0.2"]) # pylint: disable=subprocess-run-check
        return {"status": "SUCCESS", "states": {"on": params['on'], "online": True}}
    return {"status": "ERROR"}
