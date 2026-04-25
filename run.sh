#!/bin/bash
set -e

#echo "Running extractor task.."
#python3 task1/extractor.py

#echo "Running comparator task.."
#python3 task2/comparator.py

echo "Running executor task.."
python3 task3/executor.py

echo "Script complete."
