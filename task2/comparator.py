import yaml
import os

def load_yaml_files(input_path = "task2_inputs.txt"):
    with open(input_path, "r") as f:
        file1 = f.readline().strip()
        file2 = f.readline().strip()

    if not os.path.exists(file1):
        raise FileNotFoundError(f"{file1} does not exist.")
    elif not os.path.exists(file2):
        raise FileNotFoundError(f"{file2} does not exist.")

    return file1, file2


def contrast_names(file1, file2):
    with open(file1, "r") as f:
        data1 = yaml.safe_load(f)
    
    with open(file2, "r") as f:
        data2 = yaml.safe_load(f)

    names1 = { entry["name"] for entry in data1.values() }
    names2 = { entry["name"] for entry in data2.values() }
    unique_names = names1 ^ names2

    lines = []

    if len(unique_names) == 0:
        lines.append("NO DIFFERENCES IN REGARDS TO ELEMENT NAMES")
    else:
        for name in unique_names:
            lines.append(name + "\n")
    
    with open("unique_names.txt", "w") as f:
        f.writelines(lines)


def contrast_entries(file1, file2):
    with open(file1, "r") as f:
        data1 = yaml.safe_load(f)

    with open(file2, "r") as f:
        data2 = yaml.safe_load(f)

    index1 = {entry["name"]: set(entry["requirements"]) for entry in data1.values()}
    index2 = {entry["name"]: set(entry["requirements"]) for entry in data2.values()}

    lines = []

    for name in index1.keys() | index2.keys():
        reqs1 = index1.get(name)
        reqs2 = index2.get(name)

        if reqs1 is None:
            lines.append(f"{name},ABSENT-IN-{file1},PRESENT-IN-{file2},NA\n")
        elif reqs2 is None:
            lines.append(f"{name},ABSENT-IN-{file2},PRESENT-IN-{file1},NA\n")
        else:
            for req in reqs1 - reqs2:
                lines.append(f"{name},ABSENT-IN-{file2},PRESENT-IN-{file1},{req}\n")
            for req in reqs2 - reqs1:
                lines.append(f"{name},ABSENT-IN-{file1},PRESENT-IN-{file2},{req}\n")

    with open("unique_entries.txt", "w") as f:
        if len(lines) == 0:
            f.write("NO DIFFERENCES IN REGARD TO ELEMENT REQUIREMENTS")
        else:
            f.writelines(lines)




if __name__ == "__main__":
    file1, file2 = load_yaml_files()
    contrast_names(file1, file2)
    contrast_entries(file1, file2)
