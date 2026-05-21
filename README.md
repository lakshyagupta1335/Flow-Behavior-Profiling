# Manual for Flow Behavior Profiling

## Overview

Flow Behavior Profiling is a network traffic analysis and classification system developed to profile network flows based on their behavioral patterns. The system classifies traffic into categories such as normal, suspicious, and attack-like behavior using a hybrid detection architecture.

The project combines rule-based heuristics, supervised machine learning, and unsupervised anomaly detection to improve classification accuracy and support real-time traffic monitoring. The system captures live network flows, processes them through trained models, and displays the classification results on a web-based dashboard.

## Objective

The objective of this project is to perform flow behavior profiling and traffic classification using machine learning techniques and real-time network flow analysis.

The system is designed to:

- Analyze network traffic behavior
- Detect malicious or suspicious traffic patterns
- Classify traffic flows into predefined behavioral categories
Support real-time monitoring and anomaly detection

## Features
- Real-time network traffic profiling using live flow extraction (CICFlowMeter)
- Hybrid detection pipeline combining rule-based heuristics, Random Forest classification, and Isolation Forest anomaly detection
- Dedicated dashboard sections for each traffic type (Normal, Suspicious, Attack-like) for better analysis and monitoring
- Option to select active network interface (e.g., WiFi, Ethernet) for live traffic capture
- Behavioral classification of traffic into Normal, Suspicious, and Attack-like categories
- End-to-end flow-based analysis from packet capture to real-time dashboard visualization
- Live communication between backend and frontend using WebSockets for instant updates

## Dataset

The project uses the CICIDS2017 dataset collected from Kaggle:
https://www.kaggle.com/datasets/ernie55ernie/improved-cicids2017-and-csecicids2018

The dataset contains realistic network traffic generated under both benign and attack scenarios.
The dataset includes multiple attack categories such as:

- DDoS
- DoS attacks
- Port scanning
- Botnet traffic
- Web attacks
- Brute force attacks
- Infiltration attacks
- Heartbleed attacks
- SSH and FTP attacks

## ML Model Selection

Multiple supervised and unsupervised machine learning models were trained on the CICIDS2017 dataset to evaluate performance for traffic classification and anomaly detection.

Supervised models were used for labeled traffic classification, while unsupervised models were used to detect unknown or anomalous behavior.

- After evaluation, Random Forest was selected for classification due to its performance and robust behavior across network classes. 
- Isolation Forest was selected for anomaly detection due to its fast and effective detection in high-volume, unknown traffic scenarios.

## Rule-Based Heuristic System

A rule-based heuristic layer is used as the first stage of classification. It applies predefined patterns on flow features to quickly identify clearly known traffic behaviors. If a flow cannot be confidently classified using rules, it is forwarded to the machine learning pipeline for further processing.

This hybrid approach improves both classification reliability and anomaly detection capability.

## Tech Stack

| Component                     | Technology         | Purpose                                                                 |
|-------------------------------|--------------------|-------------------------------------------------------------------------|
| **Programming Language**      | Python             | Core implementation of backend logic and machine learning pipeline      |
| **Machine Learning Models**   | Scikit-learn       | Training and deployment of Random Forest and Isolation Forest models    |
| **Data Processing**           | Pandas, NumPy      | Data cleaning, preprocessing, and feature engineering                   |
| **Network Flow Extraction**   | CICFlowMeter       | Capturing real-time network traffic and generating flow-based features  |
| **Backend API**               | Flask              | Handling API requests and serving model predictions                     |
| **Real-time Communication**   | Flask-SocketIO     | WebSocket-based live communication between backend and frontend         |
| **Frontend Dashboard**        | React.js           | Visualization of traffic flows and classification results               |

## System Requirements

The system requires a standard development environment capable of running Python-based machine learning services, frontend applications, and real-time network flow processing.

- Python 3.8 or above
- Node.js 14 or above
- npm (latest version)
- Git for version control
- CICFlowMeter for real-time network flow extraction
- Minimum 8GB RAM recommended for smooth model execution and real-time processing

## Acknowledgements
This project was developed as part of the **HPE CPP-3 Program**. Gratitude to the mentors for their support and guidance throughout the development process, which helped in building and understanding a real-world system involving machine learning, network traffic analysis, and full-stack development.

## Team Members

| Name        | GitHub Profile                                            |
| ------------| --------------------------------------------------------- |
| Divesh Jain | [Diveshjain](https://github.com/Diveshjain005)              |
| Hemangini   | [HemanginiPadia](https://github.com/HemanginiPadia)       |
| Lakshya     | [lakshyagupta1335](https://github.com/lakshyagupta1335)     |
| Neelkanth   | [neelkanth-tiwadi](https://github.com/neelkanth-tiwadi)   |
| Vansh       | [VanshSwaroopVerma](https://github.com/VanshSwaroopVerma) |
