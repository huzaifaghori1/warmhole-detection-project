import numpy as np
import matplotlib.pyplot as plt
import networkx as nx
from scipy.spatial import distance
from collections import deque
import tkinter as tk
from tkinter import simpledialog, messagebox

# Predefined key for accessing the accounts file
KEY = "FAST"

# Function to generate a random Wireless Sensor Network (WSN) on a 2D plane
def generate_wsn(num_nodes, area_size):
    return np.random.rand(num_nodes, 2) * area_size

# Function to calculate distances between sensors
def calculate_distances(nodes):
    return distance.cdist(nodes, nodes)

# Function to insert a wormhole into the network
def insert_wormhole(distances, hop_distance):
    wormhole_nodes = []
    for i, row in enumerate(distances):
        if np.count_nonzero(row <= hop_distance) >= 6:
            wormhole_nodes.append(i)
    return wormhole_nodes

# Function to detect affected sensors using spanning trees and Euclidean distance approach
def detect_affected_sensors(nodes, wormhole_nodes, hop_distance):
    G = nx.Graph()
    G.add_nodes_from(range(len(nodes)))
    for i, node1 in enumerate(nodes):
        for j, node2 in enumerate(nodes):
            if i != j and distance.euclidean(node1, node2) <= hop_distance:
                G.add_edge(i, j)
    spanning_tree = nx.minimum_spanning_tree(G)
    affected_sensors = set()
    for wormhole_node in wormhole_nodes:
        visited = set()
        queue = deque()
        queue.append(wormhole_node)
        while queue:
            current_node = queue.popleft()
            if current_node not in visited:
                visited.add(current_node)
                for neighbor in spanning_tree.neighbors(current_node):
                    queue.append(neighbor)
        affected_sensors.update(visited)
    return list(affected_sensors)

# Function to visualize the network and detected wormholes
def visualize_network(nodes, wormhole_nodes, affected_sensors, user_name, distances):
    plt.figure(figsize=(12, 6))
    # Plot with wormhole detection only
    plt.subplot(1, 2, 1)
    plt.scatter(nodes[:, 0], nodes[:, 1], color='b', label='Normal Sensors')
    plt.scatter(nodes[wormhole_nodes, 0], nodes[wormhole_nodes, 1], color='r', label='Wormhole Nodes')
    plt.scatter(nodes[affected_sensors, 0], nodes[affected_sensors, 1], color='g', label='Affected Sensors')
    plt.xlabel('X-coordinate')
    plt.ylabel('Y-coordinate')
    plt.title('Wormhole Detection')
    plt.legend()
    plt.grid(True)
    # Plot with complete network
    plt.subplot(1, 2, 2)
    plt.scatter(nodes[:, 0], nodes[:, 1], color='b', label='Normal Sensors')
    plt.scatter(nodes[wormhole_nodes, 0], nodes[wormhole_nodes, 1], color='r', label='Wormhole Nodes')
    plt.scatter(nodes[affected_sensors, 0], nodes[affected_sensors, 1], color='g', label='Affected Sensors')
    plt.xlabel('X-coordinate')
    plt.ylabel('Y-coordinate')
    plt.title('Complete Network')
    for i, (x, y) in enumerate(nodes):
        plt.text(x, y, f'Device {i+1}', fontsize=8, ha='center', va='center')
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            plt.text((nodes[i, 0] + nodes[j, 0]) / 2, (nodes[i, 1] + nodes[j, 1]) / 2,
                     f'{distances[i, j]:.2f}', fontsize=8, ha='center', va='center')
    # Annotate wormhole detection
    for wormhole_node in wormhole_nodes:
        plt.text(nodes[wormhole_node, 0], nodes[wormhole_node, 1], f'Wormhole Detected', color='r', fontsize=8,
                 ha='center', va='bottom')
    plt.legend()
    plt.grid(True)
    plt.suptitle(f'Wireless Sensor Network (Viewed by: {user_name})')
    plt.tight_layout()
    plt.show()

# Function to log viewer information into a file
def log_viewer_info(user_name, num_devices, num_wormholes, wormhole_nodes, distances):
    log_file = "viewer_log.txt"
    with open(log_file, "a") as f:
        f.write(f"Viewer: {user_name}, Number of Devices: {num_devices}, Number of Wormholes Detected: {num_wormholes}\n")
        f.write("Wormhole Details:\n")
        for wormhole_node in wormhole_nodes:
            f.write(f"- Device {wormhole_node+1}: Distance to other devices:\n")
            for i, dist in enumerate(distances[wormhole_node]):
                if i != wormhole_node:
                    f.write(f"  - Device {i+1}: {dist:.2f}\n")
            f.write("\n")

# Function for user authentication using GUI
def authenticate_user():
    def create_account():
        nonlocal root
        root.withdraw()
        create_root = tk.Tk()
        create_root.title("Create Account")
        tk.Label(create_root, text="Enter a new username:").pack()
        new_username_entry = tk.Entry(create_root)
        new_username_entry.pack()
        tk.Label(create_root, text="Enter a new password:").pack()
        new_password_entry = tk.Entry(create_root, show="*")
        new_password_entry.pack()
        tk.Label(create_root, text="Enter the access key:").pack()
        access_key_entry = tk.Entry(create_root, show="*")
        access_key_entry.pack()
        
        def save_account():
            username = new_username_entry.get()
            password = new_password_entry.get()
            access_key = access_key_entry.get()
            if access_key == KEY:
                with open("accounts.txt", "a") as f:
                    f.write(f"{username}:{password}\n")
                messagebox.showinfo("Account Created", "Account created successfully!")
                create_root.destroy()
                # Ask if user wants to login
                if messagebox.askyesno("Login", "Do you want to login now?"):
                    login()
                else:
                    create_root.quit()  # Quit application if not logging in
            else:
                messagebox.showerror("Access Denied", "Incorrect access key. Account creation failed.")
        
        tk.Button(create_root, text="Create Account", command=save_account).pack()
        create_root.mainloop()

    def login():
        nonlocal root
        root.withdraw()
        login_root = tk.Tk()
        login_root.title("Login")
        tk.Label(login_root, text="Username:").pack()
        username_entry = tk.Entry(login_root)
        username_entry.pack()
        tk.Label(login_root, text="Password:").pack()
        password_entry = tk.Entry(login_root, show="*")
        password_entry.pack()
        tk.Label(login_root, text="Enter the access key:").pack()
        access_key_entry = tk.Entry(login_root, show="*")
        access_key_entry.pack()
        
        def verify_login():
            username = username_entry.get()
            password = password_entry.get()
            access_key = access_key_entry.get()
            if access_key == KEY:
                with open("accounts.txt", "r") as f:
                    accounts = [line.strip().split(":") for line in f.readlines()]
                if [username, password] in accounts:
                    messagebox.showinfo("Login Successful", "Authentication successful!")
                    login_root.destroy()
                    root.destroy()
                    main_program(username)  # Call main program with the username
                else:
                    messagebox.showerror("Login Failed", "Authentication failed. Please try again.")
            else:
                messagebox.showerror("Access Denied", "Incorrect access key. Login failed.")
        
        tk.Button(login_root, text="Login", command=verify_login).pack()
        login_root.mainloop()

    root = tk.Tk()
    root.title("Login")
    login_or_create_frame = tk.Frame(root)
    login_or_create_frame.pack(pady=10)
    
    tk.Button(login_or_create_frame, text="Login", command=login).pack(side="left", padx=5)
    tk.Button(login_or_create_frame, text="Create Account", command=create_account).pack(side="right", padx=5)
    root.mainloop()

# Function to prompt the user for their name
def prompt_for_name():
    user_name = simpledialog.askstring("Name", "Enter your name:")
    return user_name

# Main program after successful login
def main_program(username):
    # Parameters
    num_nodes = 10
    area_size = 10
    communication_radius = 2.5  # Changed radius value
    hop_distance = 6 * communication_radius

    # Generate WSN
    nodes = generate_wsn(num_nodes, area_size)

    # Calculate distances between sensors
    distances = calculate_distances(nodes)

    # Insert wormhole into the network
    wormhole_nodes = insert_wormhole(distances, hop_distance)

    # Detect affected sensors
    affected_sensors = detect_affected_sensors(nodes, wormhole_nodes, hop_distance)

    # Prompt user for their name
    user_name = prompt_for_name()

    if user_name:
        # Print number of devices and distances
        print(f"Number of devices in the network: {num_nodes}")
        print("Distances between devices:")
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                print(f"Distance between Device {i+1} and Device {j+1}: {distances[i, j]:.2f}")

        # Log viewer information
        num_wormholes = len(wormhole_nodes)
        log_viewer_info(user_name, num_nodes, num_wormholes, wormhole_nodes, distances)

        # Visualize the network and detected wormholes
        visualize_network(nodes, wormhole_nodes, affected_sensors, user_name, distances)

# Main function
def main():
    authenticate_user()

if __name__ == "__main__":
    main()
