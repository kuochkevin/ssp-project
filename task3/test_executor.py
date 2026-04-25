import pytest
import json
import pandas as pd
from unittest.mock import Mock, patch, MagicMock
import executor as e


@pytest.mark.parametrize(
    "setup_files, expect_error",
    [
        # success case
        (
            {
                "unique_names.txt": "name1\nname2\n",
                "unique_entries.txt": "entry1\nentry2\n",
            },
            False,
        ),

        # missing names file
        (
            {
                "unique_entries.txt": "entry1\nentry2\n",
            },
            True,
        ),

        # missing entries file
        (
            {
                "unique_names.txt": "name1\nname2\n",
            },
            True,
        ),
    ],
)
def test_load_inputs(tmp_path, monkeypatch, setup_files, expect_error):
    monkeypatch.chdir(tmp_path)

    # create files dynamically
    for filename, content in setup_files.items():
        (tmp_path / filename).write_text(content)

    if expect_error:
        with pytest.raises(FileNotFoundError):
            e.load_inputs("unique_names.txt", "unique_entries.txt")
    else:
        names, entries = e.load_inputs("unique_names.txt", "unique_entries.txt")

        assert names == ["name1\n", "name2\n"]
        assert entries == ["entry1\n", "entry2\n"]


@pytest.mark.parametrize(
    "names, entries, mock_llm_output, expected",
    [
        (
            ["Control A\n"],
            ["Control B\n"],
            "C-0057,C-0066",
            "C-0057,C-0066",
        ),
        (
            ["Control A\n"],
            ["Control B\n"],
            "INVALID,C-0057",
            "C-0057",
        ),
        (
            ["NO DIFFERENCES IN REGARDS TO ELEMENT NAMES\n"],
            ["NO DIFFERENCES IN REGARDS TO ELEMENT REQUIREMENTS\n"],
            None,
            "NO DIFFERENCES FOUND",
        ),
    ],
)
def test_get_controls(names, entries, mock_llm_output, expected):
    mock_pipe = Mock()

    # early return case
    if mock_llm_output is None:
        result = e.get_controls(names, entries, None)
        assert result == expected
        return

    mock_pipe.return_value = [
        {
            "generated_text": [
                {"content": mock_llm_output}
            ]
        }
    ]

    result = e.get_controls(names, entries, mock_pipe)
    assert expected in result


def test_execute_kubescape(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    # fake controls file
    controls = tmp_path / "controls.txt"
    controls.write_text("C-0057")

    # fake kubescape output JSON
    fake_json = {
        "summaryDetails": {
            "controls": {
                "C-0057": {
                    "severity": "high",
                    "ResourceCounters": {
                        "failedResources": 1,
                        "passedResources": 2,
                        "skippedResources": 0
                    },
                    "complianceScore": 80
                }
            }
        },
        "results": [
            {
                "resourceID": "test",
                "controls": [
                    {
                        "controlID": "C-0057",
                        "name": "Privileged container"
                    }
                ]
            }
        ]
    }

    def fake_run(*args, **kwargs):
        with open("kubescape_results.json", "w") as f:
            json.dump(fake_json, f)

    monkeypatch.setattr(e.subprocess, "run", fake_run)

    df = e.execute_kubescape("controls.txt", "YAMLfiles")

    assert isinstance(df, pd.DataFrame)
    assert "Control name" in df.columns
    assert len(df) > 0


def test_generate_csv(tmp_path):
    df = pd.DataFrame([
        {
            "FilePath": "x",
            "Severity": "High",
            "Control name": "Test",
            "Failed resources": 1,
            "All Resources": 2,
            "Compliance score": "90%"
        }
    ])

    output = tmp_path / "out.csv"

    path = e.generate_csv(df, str(output))

    assert output.exists()
    assert path == str(output)
