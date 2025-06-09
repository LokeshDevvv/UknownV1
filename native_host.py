#!/usr/bin/env python3
import sys
import json
import struct
import requests
import threading
from queue import Queue

# Communication queue
message_queue = Queue()

def send_message(message):
    """Send a message to the extension."""
    encoded_content = json.dumps(message).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('I', len(encoded_content)))
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()

def read_message():
    """Read a message from the extension."""
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        return None
    message_length = struct.unpack('I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode('utf-8')
    return json.loads(message)

def process_message(message):
    """Process a message from the extension."""
    try:
        if message.get('type') == 'ANALYZE_URL':
            url = message.get('url')
            response = requests.post(
                'http://localhost:5000/api/analyze',
                json={'url': url},
                headers={'Content-Type': 'application/json'}
            )
            if response.ok:
                return {'success': True, 'data': response.json()}
            else:
                return {'success': False, 'error': f'API error: {response.status_code}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def main():
    """Main message loop."""
    while True:
        try:
            message = read_message()
            if message is None:
                break
            
            response = process_message(message)
            if response:
                send_message(response)
        except Exception as e:
            send_message({'success': False, 'error': str(e)})
            break

if __name__ == '__main__':
    main() 