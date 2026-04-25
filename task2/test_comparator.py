import pytest
import yaml
import comparator as c

def test_load_yaml_files(tmp_path, monkeypatch):
    base = tmp_path
    monkeypatch.chdir(base)

    # create fake yaml files
    file1 = base / "file1.yaml"
    file2 = base / "file2.yaml"
    file1.write_text("a: 1")
    file2.write_text("b: 2")

    # create input pointer file
    input_file = base / "task2_inputs.txt"
    input_file.write_text("file1.yaml\nfile2.yaml\n")

    f1, f2 = c.load_yaml_files()

    assert "file1.yaml" in f1
    assert "file2.yaml" in f2


@pytest.mark.parametrize(
    "data1, data2, expected_in_output",
    [
        # Case 1: differences exist
        (
            {"e1": {"name": "Alpha", "requirements": []}},
            {"e1": {"name": "Beta", "requirements": []}},
            None  # we just check output file contains something not equal
        ),

        # Case 2: no differences
        (
            {"e1": {"name": "Same", "requirements": []}},
            {"e1": {"name": "Same", "requirements": []}},
            "NO DIFFERENCES IN REGARDS TO ELEMENT NAMES"
        ),
    ],
)
def test_contrast_names_combined(tmp_path, monkeypatch, data1, data2, expected_in_output):
    base = tmp_path
    monkeypatch.chdir(base)

    file1 = base / "f1.yaml"
    file2 = base / "f2.yaml"

    file1.write_text(yaml.safe_dump(data1))
    file2.write_text(yaml.safe_dump(data2))

    c.contrast_names(str(file1), str(file2))

    output = base / "unique_names.txt"
    content = output.read_text()

    if expected_in_output:
        assert expected_in_output in content
    else:
        # just ensure something was written
        assert len(content.strip()) > 0


@pytest.mark.parametrize(
    "data1, data2, expected_contains",
    [
        # Case 1: requirement differences
        (
            {
                "e1": {
                    "name": "ControlA",
                    "requirements": ["req1", "req2"]
                }
            },
            {
                "e1": {
                    "name": "ControlA",
                    "requirements": ["req2", "req3"]
                }
            },
            ["req1", "req3"]
        ),

        # Case 2: identical requirements
        (
            {
                "e1": {
                    "name": "ControlA",
                    "requirements": ["req1"]
                }
            },
            {
                "e1": {
                    "name": "ControlA",
                    "requirements": ["req1"]
                }
            },
            ["NO DIFFERENCES IN REGARD TO ELEMENT REQUIREMENTS"]
        ),

        # Case 3: element missing in file1
        (
            {},
            {
                "e1": {
                    "name": "ControlA",
                    "requirements": ["req1"]
                }
            },
            ["ABSENT-IN-"]
        ),

        # Case 4: element missing in file2
        (
            {
                "e1": {
                    "name": "ControlA",
                    "requirements": ["req1"]
                }
            },
            {},
            ["ABSENT-IN-"]
        ),
    ],
)
def test_contrast_entries_combined(tmp_path, monkeypatch, data1, data2, expected_contains):
    base = tmp_path
    monkeypatch.chdir(base)

    file1 = base / "f1.yaml"
    file2 = base / "f2.yaml"

    file1.write_text(yaml.safe_dump(data1))
    file2.write_text(yaml.safe_dump(data2))

    c.contrast_entries(str(file1), str(file2))

    output = base / "unique_entries.txt"
    content = output.read_text()

    for expected in expected_contains:
        assert expected in content
