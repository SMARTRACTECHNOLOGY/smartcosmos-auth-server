FROM smartcosmos/service
MAINTAINER SMART COSMOS Platform Core Team

ADD target/smartcosmos-*.jar  /opt/smartcosmos/smartcosmos-auth-server.jar

CMD ["/opt/smartcosmos/smartcosmos-auth-server.jar"]
