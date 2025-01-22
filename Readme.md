# Log Analysis Script

This script analyzes log files for suspicious activity patterns and saves the results to CSV files.

## Requirements

- Python 3.x
- `rich` library for enhanced terminal output

## Installation

1. Clone the repository:
    ```sh
    git clone <repository_url>
    cd <repository_directory>
    ```

2. Install the required dependencies:
    ```sh
    pip install rich
    ```

## Usage

To run the script, use the following command:

```sh
python log-parser.py -f <folder_path>
```

Replace `<folder_path>` with the path to the directory containing the log files you want to analyze.

## Example

```sh
python log-parser.py -f /path/to/log/files
```

## Output

The script will analyze all log files in the specified directory and save the results to separate CSV files for each suspicious activity pattern.

## License

This project is licensed under 