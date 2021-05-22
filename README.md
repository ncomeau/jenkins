# myjenkins
Testing jenkins-server 

  - docker.sock mounted as volume so jenkins server can also run docker
  - Add cbctl to app folder (or to your /var/jenkins/) before building to copy to jenkins server. After jenkins is running remember to update cbctl creds

**Setup**

Build image:
  - sudo docker build . -t <image/name>

Confirm docker engine is installed:
  - docker --version

**Run with docker:**

  - docker run \
          --name jenkins-server \
          --publish 8080:8080 \
          --publish 50000:50000 \
          --volume /var/jenkins:/var/jenkins_home \
	        --volume /var/run/docker.sock:/var/run/docker.sock \
          <image/name>
	  
**OR - Run as service**

Setup jenkins user:
  - sudo groupadd --system jenkins
  - sudo useradd -s /sbin/nologin --system -g jenkins jenkins
  - sudo mkdir /var/jenkins
  - sudo chown -R 1000:1000 /var/jenkins

Create service for systemd:
  - sudo vi /etc/systemd/system/jenkins-docker.service
  - copy in jenkins-docker.service and update image name

Start jenkins-docker as service:
  - sudo systemctl daemon-reload
  - sudo systemctl start jenkins-docker
  
Source of setup steps:
https://computingforgeeks.com/running-jenkins-server-in-docker-container-systemd/
