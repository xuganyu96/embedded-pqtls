#!/usr/bin/env python3

import sys
import serial
import argparse

def read_serial(port, baudrate, log_file=None):
    try:
        # Open serial port
        ser = serial.Serial(port, baudrate=baudrate, timeout=1)
        print(f"Reading from {port} at {baudrate} baud...")
        
        # Open log file if specified
        log = open(log_file, "a") if log_file else None

        while True:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if line:
                print(line)  # Print to stdout
                if log:
                    log.write(line + "\n")  # Write to log file
                    log.flush()
    except serial.SerialException as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        if 'ser' in locals() and ser.is_open:
            ser.close()
        if log:
            log.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read from a serial port and output to stdout (and optional log file).")
    parser.add_argument("port", help="Serial port (e.g., /dev/ttyUSB0, COM3)")
    parser.add_argument("-b", "--baudrate", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("-C", "--logfile", help="Log file to write output to")

    args = parser.parse_args()
    read_serial(args.port, args.baudrate, args.logfile)
