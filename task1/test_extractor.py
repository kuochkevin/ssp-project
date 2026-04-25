import pytest
import os
import yaml
from unittest.mock import Mock, patch, MagicMock
import extractor as ex


@patch("extractor.os.path.getsize", return_value=100)
@patch("extractor.os.path.exists", return_value=True)
@patch("extractor.fitz.open")
def test_load_document_valid_pdf(mock_open, mock_exists, mock_getsize):
    mock_doc = MagicMock()
    mock_page = MagicMock()
    mock_page.get_text.return_value = "security requirement text"

    mock_doc.__len__.return_value = 1
    mock_doc.__iter__.return_value = [mock_page]

    mock_open.return_value = mock_doc

    result = ex.load_document("fake.pdf")

    assert "security requirement text" in result

def test_construct_zero_shot_prompt():
    text = "sample document"
    prompt = ex.construct_zero_shot_prompt(text)

    assert text in prompt
    assert "You are an expert Security Requirements Analyst" in prompt


def test_construct_few_shot_prompt():
    text = "sample document"

    prompt = ex.construct_few_shot_prompt(text)

    assert "EXAMPLES" in prompt
    assert text in prompt


def test_construct_chain_of_thought_prompt():
    text = "sample document"

    prompt = ex.construct_chain_of_thought_prompt(text)

    assert "REASONING FORMAT" in prompt
    assert text in prompt
    

def test_get_kde_output_structure():
    pipe = Mock()

    pipe.return_value = [
        {
            "generated_text": [
                {"content": "fake output"}
            ]
        }
    ]

    with patch.object(ex, "parse_llm_output_to_dict", return_value={"a": 1}):
        result = ex.get_kde("prompt", pipe)

    assert result == {"a": 1}


def test_collect_output(tmp_path):
    file_path = tmp_path / "output.txt"

    zero = {"element_1": {"name": "A", "requirements": ["req1"]}}
    few = {"element_1": {"name": "B", "requirements": ["req2"]}}
    chain = {"element_1": {"name": "C", "requirements": ["req3"]}}

    ex.collect_output(str(file_path), zero, few, chain)

    assert file_path.exists()

    content = file_path.read_text()
    assert "Zero Shot" in content
    assert "Few Shot" in content
    assert "Chain of Thought" in content



