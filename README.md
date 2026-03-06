# Description

![alt text](images/logo.svg)

Headlamp is a tool which replaces the old NIRD Kubernetes dashboard. It allows the users to manage their pods and services using a graphical interface, check the events and the logs and log into their pods in a terminal mode.

# Download

The tool Headlamp can be downloaded from here: 

https://headlamp.dev/

(This is the routine for Linux, for the other OS, check the link **Install on other platforms**)

Select the *Headlamp-0.40.1-linux-x64.tar.gz* version in the dropdown `Download for Linux`:

![alt text](images/select-headlamp-version.png)


# Installation 

## Step 1 

Please make sure you do not have a process `nird-toolkit-auth-helper` (or another name) running on port 49999!

* In Linux,  try `netstat -tulnap`, get the process number and run `kill -9 PROCESS-NUMBER`.
* Im MacOS, try `lsof -nP -iTCP -sTCP:LISTEN`, get the process number and run `kill -9 PROCESS-NUMBER`.

If you have a process running on this port from before it will spawn a big number of broswer tabs pointing at Feide site when you launch *Headlamp*. 

The process `nird-toolkit-auth-helper` must not be running whan you launch _Headlamp_!


## Step 2 

The Headlamp binary is located in `Headlamp-0.40.1-linux-x64/headlamp`. Start the binary. It will automatically run a browser with a Feide authentication window. Follow the steps until you see a success message in your browser window. CLose the window and go the the Headlamp dashboard.

## Step 3

Go to the Add Cluster button in the left lower corner of the dashboard.

![alt text](images/add-cluster-button.png)

If the cluster is not already selected by using the context from `.kube/config` file add the name nird-lmd.

When you see the cluster list (here `nird-lmd`) 

![alt text](images/cluster-list-user.png)

select the cluster.

In the next page, go to `Namspaces` and select the one you have access to.

![alt text](images/namespaces.png)

