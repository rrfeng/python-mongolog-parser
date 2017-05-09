#!/usr/bin/env python
import re
import sys
import yaml
import json

class LogEvent:
    def __init__(self, line):
        self.log = {}
        self._re_in = re.compile(r'\$in: \[[^\]]+\]')
        self._re_objid = re.compile(r'ObjectId\(\'[0-9a-f]{24}\'\)')
        try:
            self.tokens = re.split(' +', line)
            self.log['time'] = self.tokens[0]
            self.log['level'] = self.tokens[1]
            self.log['type'] = self.tokens[2]
            self.log['session'] = self.tokens[3][1:-1]

            # if last one is `117ms`
            match = re.match(r'(\d+)ms$', self.tokens[-1])
            if match:
                self.log['duration'] = int(match.group(1))
                self.tokens.pop()

            self._message = self.tokens[4:]
        except Exception as e:
            raise e

    def _drop_warning_of_too_long(self):
        while self._message.pop(0) != "...":
            continue

    def _get_close_brackets(self):
        idx = 0
        count = 1
        if self._message[idx] != '{':
            return []
        
        while count != 0:
            idx = idx + 1
            if self._message[idx] == '{':
                count = count + 1
            elif self._message[idx] == '}' or self._message[idx] == '},':
                count = count - 1
            else:
                continue

        result = self._message[:idx] + ['}'] # strip the ending ','

        self._message = self._message[idx+1:]

        return result

    def _drop_ids_query_str(self):
        self._query_str = self._re_in.sub('$in: [...]', self._query_str, count=0)
        self._query_str = self._re_objid.sub('ObjectId(...)', self._query_str, count=0)

        self.log['query_str'] = self._query_str

    def Parse(self):
        if self.log['type'] != "COMMAND":
            self.log['text'] = ' '.join(self.tokens[4:]).strip()
            return

        # Parse the rest:
        while len(self._message) > 0:
            token = self._message.pop(0)
            if token == "warning:":
                self._drop_warning_of_too_long()

            elif token == "killcursors":
                self.log['namespace'] = self._message.pop(0)
                self.log['command'] = token

            elif token == "command":
                # `command keepdb.users command: find {...}`
                self.log['namespace'] = self._message.pop(0)
                self._message.pop(0)
                self.log['command'] = self._message.pop(0)
                self._query_str = ' '.join(self._get_close_brackets())

            elif token == "query":
                # `query keepdb.users query: {...}`
                self.log['namespace'] = self._message.pop(0)
                self.log['command'] = self._message.pop(0)
                self._query_str = ' '.join(self._get_close_brackets())

            elif token == "getmore":
                self.log['namespace'] = self._message.pop(0)
                self.log['command'] = token
                if self._message[0] != 'planSummary:':
                    self._message.pop(0)
                    self._query_str = ' '.join(self._get_close_brackets())

            elif token == "serverStatus":
                self.log['command'] = token
                return

            elif token == "planSummary:":
                self.log['query_plan'] = self._message.pop(0)
                if self.log['query_plan'] == 'IXSCAN':
                    self.log['query_index'] = ' '.join(self._get_close_brackets())

            elif token == "IXSCAN":
                _query_index_more = ' '.join(self._get_close_brackets())
                if _query_index_more != self.log['query_index']:
                    try:
                        self.log['query_index_more'].append(_query_index_more)
                    except Exception:
                        self.log['query_index_more'] = []
                        self.log['query_index_more'].append(_query_index_more)

            elif token == "locks:{":
                # `locks:{ Global: ...}`
                self._message.insert(0, '{')
                _locks = ' '.join(self._get_close_brackets())
                try:
                    self.log['locks'] = yaml.load(_locks)
                except Exception as e:
                    print e

            elif token == "exception:":
                self.log['exception'] = token
                while True:
                    next_token = self._message.pop(0)
                    self.log['exception'] += (' ' + next_token)
                    if re.match('^code:\d+$', next_token):
                        break

            else:
                m = re.match(r'([a-zA-z]+):([0-9]+)', token)
                if m:
                    self.log[m.group(1)] = int(m.group(2))
                else:
                    n = re.match(r'([a-zA-z]+):([^:]+)', token)
                    if n:
                        self.log[n.group(1)] = n.group(2)
                    else:
                        if  'errors' not in self.log:
                            self.log['errors'] = ''
                        self.log['errors'] += (' ' + token)

        try:
            self._drop_ids_query_str()
        except Exception:
            pass

if __name__ == "main":
    for message in sys.stdin:
        try:
            event = LogEvent(message)
            event.Parse()
            line = event.log
        except Exception as e:
            sys.stderr.write(message, e)
        print json.dumps(line)
