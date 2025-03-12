# Mulesoft Flex Phantom Token Policy

[![Quality](https://img.shields.io/badge/quality-experiment-red)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

A custom policy for the Mulesoft Flex Gateway to introspect opaque access tokens and forward JWTs to APIs 

## Overview

## Prerequisites

## Building the Policy

`make build`

## Publishing the Policy

`make publish`

## Configuration

Parameter | Description |
--------- | ----------- |
Introspection Endpoint | The introspection endpoint of The Curity Identity Server
Introspection Client | The client_id of a client with the `introspection` capability
Introspection Secret | The secret of the client with the `introspection` capability
Required Audience | The value of the `aud` claim in the token required for access
Required Issuer | The value of the `iss` claim in the token required for access
Required Scope(s) | Required scopes for API access (space separated string)
Use 'application/jwt' Header | Boolean value the configures if the `application/jwt` header approach should be used for introspection. This returns the JWT directly in the introspection response. 
Token Extractor | The method Mulesoft Flex uses to extract the token in the Authorization header. (Can typically be left as default)

## More Information

* Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.
* [Use API Gateway Lambda authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)

Copyright (C) 2025 Curity AB.