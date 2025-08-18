# GDoS - GraphQL DoS Testing Tool

GDoS (GraphQL DoS) is a powerful and flexible tool for penetration testers and security professionals to perform Denial of Service (DoS) testing on GraphQL endpoints. It allows testing of various GraphQL vulnerabilities through multiple attack types, including Directive Overloading, Deep Introspection, Cyclic Query Attacks, and Batching Attacks.

This tool is designed to be flexible, user-friendly, and easy to use, enabling security professionals to easily execute complex DoS tests against GraphQL servers.

## Features

- **Multiple Attack Types**: Supports four different DoS attack strategies on GraphQL endpoints:
  1. **Directive Overloading**: Overload the GraphQL endpoint with excessive directives.
  2. **Deep Introspection**: Perform a recursive introspection query to stress the server.
  3. **Cyclic Query Attack**: Trigger cyclic queries that can exhaust the server’s resources.
  4. **Batching Attack**: Send batched queries to overload the server.
  
- **User-Friendly Header Input**: 
  - Enter just the **Authorization token** or **paste full headers** from tools like Burp Suite.
  - The tool will intelligently use default headers or allow you to customize them.

- **Flexible Configuration**: 
  - Set the **number of threads** and **request delay** to simulate real-world traffic.
  - Test different endpoints with customized settings.

## Requirements

- Python 3.x
- `requests` library

To install the necessary dependencies, run the following command:
```bash
pip install requests
```

## Usage
### Run the Program: After cloning this repository, you can run the program with the following command:

```bash
python gdos.py
```
### Input Headers: When prompted, you can choose between:

- Entering a token (only the Authorization header is required).
- Pasting all headers from a tool like Burp Suite or Postman.

### Choose Attack Type: You will be prompted to select the attack type by entering a number:

1: Directive Overloading
2: Deep Introspection Query
3: Cyclic Query Attack
4: Batching Attack

- **Configure Threads and Delay**: Specify the number of threads (default is 10) and the delay between requests (default is 0 seconds).

-  **Run the Attack**: Once you enter all the details, the script will execute the selected attack, providing output for each request sent, including status codes and response snippets.

## Example Usage
1. Enter the URL and headers:
```
Enter GraphQL URL (for example: https://api.example.com/graphql): https://graphql.example.com/api
Would you like to enter just the token (1) or paste all headers (2)? Enter 1 or 2: 1
Enter your Authorization token (without 'Bearer '): ABCD1234
```
2. Select Attack Type:
```
Select the attack type:
1. Directive Overloading
2. Deep Introspection Query
3. Cyclic Query Attack
4. Batching Attack
Enter the number of the test type: 1
```
3. Set Threads and Delay:
```
Enter number of threads (default 10): 5
Enter request delay (seconds, default 0.0): 1.0
```
The program will now execute the selected attack, printing status messages and response snippets to the terminal.

## Code Structure
- `get_headers_input`: Handles intelligent header input, allowing users to provide either just a token or paste full headers.
- `GraphQLDoSTest`: The base class for all DoS tests, defining the common structure and methods.
- `DirectiveOverloadingTest`, `DeepIntrospectionTest`, `CyclicQueryAttackTest`, `BatchingAttackTest`: These are subclasses of GraphQLDoSTest, each implementing a specific DoS attack type.
- **Multithreading**: Uses Python's threading module to simulate concurrent requests for high-load scenarios.
- **User Input**: Prompts the user for necessary details such as URL, headers, attack type, number of threads, and request delay.

## Contributing
If you would like to contribute to the development of this tool, please feel free to fork the repository, create a pull request, or submit issues for bug reports or feature requests.

## License
This project is licensed under the MIT License.
