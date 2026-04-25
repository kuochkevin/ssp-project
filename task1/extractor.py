import os
import fitz
from transformers import pipeline
import torch
import yaml
import re


MODEL = "google/gemma-3-1b-it"

ZERO_SHOT_TEMPLATE = """
    You are an expert Security Requirements Analyst. 
    
    TASK:
    Extract specific security configurations (Key Data Elements) and their verbatim requirements from the provided text.
    
    EXTRACTION RULES:
    1. GRANULARITY: Each KDE must represent a SINGLE and UNIQUE specific control (e.g., "Secret Encryption" or "Node Restriction"). 
    2. VERBATIM: Copy requirements exactly. Do not include status tags like "(Manual)", "(Automated)", or "(Scored)".
    3. NO METADATA: Ignore administrative labels, "Default Values", "Audit Procedures", or "Remediations". Extract only the security requirement itself.
    4. CLEANLINESS: Your response must be valid YAML. Do not include any commentary, "deactivation" notes, or conversational filler.

    OUTPUT FORMAT (YAML ONLY):
    - element_1:
        name: <specific configuration name>
        requirements:
          - <requirement text>

    Now extract from the following text:

    {document_text}
    """

FEW_SHOT_TEMPLATE = """
    You are an expert Security Requirements Analyst.

    TASK:
    Extract specific security configurations (Key Data Elements) and their verbatim requirements from the provided text.

    EXTRACTION RULES:
    1. GRANULARITY: Each KDE must represent a SINGLE and UNIQUE specific control (e.g., "Secret Encryption" or "Node Restriction"). 
    2. VERBATIM: Copy requirements exactly. Do not include status tags like "(Manual)", "(Automated)", or "(Scored)".
    3. NO METADATA: Ignore administrative labels, "Default Values", "Audit Procedures", or "Remediations". Extract only the security requirement itself.
    4. CLEANLINESS: Your response must be valid YAML. Do not include any commentary, "deactivation" notes, or conversational filler.

    EXAMPLES:

    Input Text:
    "1.1.1 Ensure that the API server pod specification file permissions are set to 600 or more restrictive (Automated)
     Default Value: By default, the API server pod specification file has permissions of 640.
     Remediation: Run the command: chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml"

    Correct Output:
    - element_1:
        name: API Server Pod Specification File Permissions
        requirements:
          - Ensure that the API server pod specification file permissions are set to 600 or more restrictive.

    ---

    Input Text:
    "3.2.1 Ensure that a minimal audit policy is created (Manual)
     3.2.2 Ensure that the audit policy covers the key security concerns (Manual)
     Default Value: Unless the --audit-policy-file flag is specified, no auditing is carried out."

    Correct Output:
    - element_1:
        name: Minimal Audit Policy
        requirements:
          - Ensure that a minimal audit policy is created.
    - element_2:
        name: Audit Policy Coverage
        requirements:
          - Ensure that the audit policy covers the key security concerns.

    ---

    Input Text:
    "5.1.1 Ensure that the cluster-admin role is only used where required (Manual)
     5.1.2 Minimize access to secrets (Manual)
     5.1.3 Minimize wildcard use in Roles and ClusterRoles (Automated)"

    Correct Output:
    - element_1:
        name: Cluster Admin Role Usage
        requirements:
          - Ensure that the cluster-admin role is only used where required.
    - element_2:
        name: Secret Access Minimization
        requirements:
          - Minimize access to secrets.
    - element_3:
        name: Wildcard Use Minimization
        requirements:
          - Minimize wildcard use in Roles and ClusterRoles.

    ---

    Your response should be in the following format:
    OUTPUT FORMAT (YAML ONLY):
    - element_1:
        name: <specific configuration name>
        requirements:
          - <requirement text>


    Now extract from the following text:

    {document_text}
    """


CHAIN_OF_THOUGHT_TEMPLATE = """
    You are an expert Security Requirements Analyst.

    TASK:
    Extract specific security configurations (Key Data Elements) and their verbatim requirements from the provided text.

    INSTRUCTIONS:
    You MUST think step-by-step and SHOW your reasoning before producing the final YAML.

    REASONING FORMAT:
    Step 1: Identify all candidate security controls.
    Step 2: Filter out non-requirement content (metadata, defaults, remediation).
    Step 3: Normalize each control into a clear name.
    Step 4: Extract the exact requirement text.

    Then produce the final answer.

    ---

    EXAMPLE:

    Input Text:
    "5.1.1 Ensure that the cluster-admin role is only used where required (Manual)
     5.1.2 Minimize access to secrets (Manual)
     Default Value: None"

    Reasoning:
    Step 1: Found two controls: cluster-admin usage, secret access.
    Step 2: Ignored "Default Value" because it is metadata.
    Step 3: Normalized names:
    - Cluster Admin Role Usage
    - Secret Access Minimization
    Step 4: Extracted requirements:
    - Ensure that the cluster-admin role is only used where required.
    - Minimize access to secrets.

    Final Answer:
    - element_1:
        name: Cluster Admin Role Usage
        requirements:
          - Ensure that the cluster-admin role is only used where required.
    - element_2:
        name: Secret Access Minimization
        requirements:
          - Minimize access to secrets.

    ---

    Now extract from the following text:

    {document_text}
    """

def load_document(file_path: str) -> str:
    """
    Validates and loads a PDF file.

    Args:
        file_path: Path to the PDF file.

    Returns:
        Validated text as a string.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not a PDF, is empty, has no pages, or contains no extractable text.
        RuntimeError: If the PDF file cannot be opened.
    """
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} not found")

    if not file_path.lower().endswith(".pdf"):
        raise ValueError(f"{file_path} is not a PDF")

    if os.path.getsize(file_path) == 0:
        raise ValueError(f"{file_path} is empty")

    try:
        doc = fitz.open(file_path)
    except Exception as e:
        raise RuntimeError(f"{file_path} could not be opened: {e}")

    if len(doc) == 0:
        raise ValueError(f"{file_path} has no pages")

    text = ''
    for page in doc:
        text += page.get_text()

    doc.close()

    if len(text) == 0:
        raise ValueError(f"{file_path} contains no extractable text")

    return text


def construct_zero_shot_prompt(document_text: str):
    return ZERO_SHOT_TEMPLATE.format(document_text=document_text)

def construct_few_shot_prompt(document_text: str):
    return FEW_SHOT_TEMPLATE.format(document_text=document_text)

def construct_chain_of_thought_prompt(document_text: str):
    return CHAIN_OF_THOUGHT_TEMPLATE.format(document_text=document_text)




def get_kde(prompt: str, pipe):
    """Runs LLM to generate KDEs and cleans/parses YAML output."""

    # Build message in chat format
    messages = [
        {"role": "user", "content": [{"type": "text", "text": prompt}]}
    ]

    # Run the LLM
    output = pipe(messages, max_new_tokens=1024, repetition_penalty=1.2)
    raw_text = output[0]['generated_text'][-1]['content']
    
    print("\n--- RAW LLM OUTPUT ---")
    print(raw_text)
    print("----------------------\n")

    return parse_llm_output_to_dict(raw_text)    


def parse_llm_output_to_dict(raw_output: str) -> dict:
    # Remove fancy quotes
    cleaned = raw_output.replace('\u201C', '')  # remove left smart quote
    cleaned = cleaned.replace('\u201D', '')  # remove right smart quote
    cleaned = cleaned.replace('\u2018', '')  # left single smart quote
    cleaned = cleaned.replace('\u2019', '')  # right single smart quote

    # Remove markdown code fences
    cleaned = re.sub(r'```yaml|```', '', cleaned).strip()
    # Remove the RAW LLM OUTPUT header/footer if present
    cleaned = re.sub(r'---.*?---', '', cleaned, flags=re.DOTALL).strip()
    
    result = {}
    current_element = None
    current_section = None

    for line in cleaned.split('\n'):
        # Fix missing space after dash before quote e.g. -"text"
        line = re.sub(r'-"', '- "', line)
        # Remove trailing periods after closing quote
        line = re.sub(r'"\.\s*$', '"', line)
        
        stripped = line.strip()
        
        if not stripped:
            continue

        # Match element key e.g. "- element_1:"
        element_match = re.match(r'-?\s*(element_\d+)\s*:', stripped)
        if element_match:
            current_element = element_match.group(1)
            result[current_element] = {'name': '', 'requirements': []}
            current_section = None
            continue

        if current_element is None:
            continue

        # Match name field
        name_match = re.match(r'name\s*:\s*(.+)', stripped)
        if name_match:
            result[current_element]['name'] = name_match.group(1).strip().strip('"')
            current_section = 'name'
            continue

        # Match requirements field
        if re.match(r'requirements\s*:', stripped):
            current_section = 'requirements'
            continue

        # Match a requirement list item
        req_match = re.match(r'-\s*"?(.+?)"?\s*$', stripped)
        if req_match and current_section == 'requirements':
            req_text = req_match.group(1).strip().strip('"').rstrip('.')
            if req_text:
                result[current_element]['requirements'].append(req_text)

    return result


def get_combined_dict(dicts):
    combined = {}
    idx = 1

    for data in dicts:
        for element in data.values():
            key = f"element_{idx}"

            combined[key] = {
                "name": element["name"],
                "requirements": element.get("requirements", [])
            }

            idx += 1

    return combined


def collect_output(file_name, zero_shot, few_shot, chain):
    with open(file_name, "w") as f:
        f.write("Model: " + MODEL + "\n")

        f.write("\n*Prompt Used*\n")
        f.write(ZERO_SHOT_TEMPLATE + "\n\n")
        f.write("Prompt Type: Zero Shot\n\n")
        f.write("*LLM Output*\n")
        yaml.safe_dump(zero_shot, f, sort_keys=False)

        f.write("\n*Prompt Used*\n")
        f.write(FEW_SHOT_TEMPLATE + "\n\n")
        f.write("Prompt Type: Few Shot\n\n")
        f.write("*LLM Output*\n")
        yaml.safe_dump(few_shot, f, sort_keys=False)
        
        f.write("\n*Prompt Used*\n")
        f.write(CHAIN_OF_THOUGHT_TEMPLATE + "\n\n")
        f.write("Prompt Type: Chain of Thought\n\n")
        f.write("*LLM Output*\n")
        yaml.safe_dump(chain, f, sort_keys=False)


def perform_task_1(input_name, output_name, pipe):
    document_text = load_document(input_name)[:15000]

    zero_kde = get_kde(construct_zero_shot_prompt(document_text), pipe)
    few_kde = get_kde(construct_few_shot_prompt(document_text), pipe)
    chain_kde = get_kde(construct_chain_of_thought_prompt(document_text), pipe)

    combined_kdes = get_combined_dict([zero_kde, few_kde, chain_kde])

    with open(output_name + "-kdes.yaml", "w") as f:
        yaml.safe_dump(combined_kdes, f, sort_keys=False)

    collect_output(output_name + "-output.txt", zero_kde, few_kde, chain_kde)

    return output_name + "-kdes.yaml"

if __name__ == "__main__":
    file1 = input("Enter the first file: ")
    file2 = input("Enter the second file: ")

    pipe = pipeline(
        "text-generation", 
        model="google/gemma-3-1b-it", 
        device="cpu", 
        torch_dtype=torch.bfloat16
    )

    output1 = file1.split('.')[0]
    output2 = file2.split('.')[0]

    if file1 == file2:
        output1 += "-1"
        output2 += "-2"

    output1 = perform_task_1(file1, output1, pipe) 
    output2 = perform_task_1(file2, output2, pipe)

    with open("task2_inputs.txt", "w") as f:
        f.write(f"{output1}\n")
        f.write(f"{output2}\n")
