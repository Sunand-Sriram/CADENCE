from crs_core.agents import slice_function


code, function_name, start_line, end_line = slice_function(
    "targets/target/vuln.c", 6
)
print(f"function_name: {function_name}")
print(f"start_line: {start_line}")
print(f"end_line: {end_line}")
print("code:")
print(code)
