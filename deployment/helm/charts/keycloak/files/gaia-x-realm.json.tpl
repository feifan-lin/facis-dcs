{
  "realm": "gaia-x",
  "displayName": "GAIA-X",
  "enabled": true,
  "sslRequired": "none",
  "registrationAllowed": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": false,
  "editUsernameAllowed": false,
  "bruteForceProtected": false,
  "roles": {
    "realm": [
      {
        "name": "uma_authorization",
        "description": "${role_uma_authorization}"
      },
      {
        "name": "offline_access",
        "description": "${role_offline-access}"
      },
      {
        "name": "default-roles-gaia-x",
        "description": "${role_default-roles}"
      },
      {
        "name": "eid-holder-natural-person",
        "description": "A natural person allowed to request a PID credential"
      }
    ],
    "client": {
      "federated-catalogue": [
        {
          "name": "Ro-SD-A"
        },
        {
          "name": "Ro-PA-A"
        },
        {
          "name": "uma_protection"
        },
        {
          "name": "ADMIN_ALL"
        },
        {
          "name": "Ro-MU-CA",
          "composite": true,
          "composites": {
            "client": {
              "federated-catalogue": [
                "Ro-SD-A",
                "Ro-PA-A",
                "Ro-MU-A",
                "ADMIN_ALL"
              ]
            }
          }
        },
        {
          "name": "Ro-MU-A"
        },
        {
          "name": "SCHEMA_CREATE"
        },
        {
          "name": "SCHEMA_READ"
        },
        {
          "name": "SCHEMA_UPDATE"
        },
        {
          "name": "SCHEMA_DELETE"
        }
      ]
    }
  },
  "scopeMappings": [
    {
      "clientScope": "eu.europa.ec.eudi.pid_vc_sd_jwt",
      "roles": [
        "eid-holder-natural-person"
      ]
    }
  ],
  "users": [
    {
      "username": "service-account-federated-catalogue",
      "enabled": true,
      "serviceAccountClientId": "federated-catalogue",
      "realmRoles": [
        "default-roles-gaia-x"
      ],
      "clientRoles": {
        "federated-catalogue": [
          "uma_protection"
        ],
        "realm-management": [
          "manage-users",
          "view-users",
          "view-clients"
        ]
      }
    },
    {
      "username": "service-account-dcs-fc-client",
      "enabled": true,
      "serviceAccountClientId": "dcs-fc-client",
      "realmRoles": [
        "default-roles-gaia-x"
      ],
      "clientRoles": {
        "federated-catalogue": [
          "Ro-MU-A",
          "Ro-SD-A",
          "Ro-PA-A",
          "Ro-MU-CA",
          "SCHEMA_CREATE",
          "SCHEMA_READ",
          "SCHEMA_UPDATE",
          "SCHEMA_DELETE",
          "uma_protection"
        ]
      }
    },
    {
      "username": "test",
      "enabled": true,
      "email": "test@gaia-x.local",
      "emailVerified": true,
      "firstName": "Test",
      "lastName": "User",
      "credentials": [
        {
          "type": "password",
          "value": "test",
          "temporary": false
        }
      ],
      "realmRoles": [
        "default-roles-gaia-x"
      ],
      "clientRoles": {
        "federated-catalogue": [
          "Ro-MU-CA",
          "Ro-SD-A",
          "Ro-PA-A",
          "Ro-MU-A"
        ]
      }
    },
    {
      "username": "johndoe",
      "enabled": true,
      "email": "johndoe@gaia-x.local",
      "emailVerified": true,
      "firstName": "John",
      "lastName": "Doe",
      "attributes": {
        "birthdate": ["1985-03-14"],
        "gender": ["1"],
        "gender_as_string": ["male"],
        "street": ["Hauptstrasse"],
        "address_house_number": ["21"],
        "locality": ["Cologne"],
        "region": ["North Rhine-Westphalia"],
        "postal_code": ["50667"],
        "country": ["DE"],
        "birth_country": ["DE"],
        "birth_city": ["Cologne"],
        "birth_place": ["Cologne"],
        "nationality": ["DE"],
        "birth_family_name": ["Doe"],
        "birth_given_name": ["John"],
        "personal_administrative_number": ["DE-PID-TEST-JOHN"]
      },
      "credentials": [
        {
          "type": "password",
          "value": "johndoe",
          "temporary": false
        }
      ],
      "realmRoles": [
        "default-roles-gaia-x",
        "eid-holder-natural-person"
      ],
      "clientRoles": {
        "federated-catalogue": [
          "Ro-MU-CA",
          "Ro-SD-A",
          "Ro-PA-A",
          "Ro-MU-A"
        ]
      }
    },
    {
      "username": "janesmith",
      "enabled": true,
      "email": "janesmith@gaia-x.local",
      "emailVerified": true,
      "firstName": "Jane",
      "lastName": "Smith",
      "attributes": {
        "birthdate": ["1990-09-08"],
        "gender": ["2"],
        "gender_as_string": ["female"],
        "street": ["Koenigstrasse"],
        "address_house_number": ["5"],
        "locality": ["Stuttgart"],
        "region": ["Baden-Wuerttemberg"],
        "postal_code": ["70173"],
        "country": ["DE"],
        "birth_country": ["DE"],
        "birth_city": ["Stuttgart"],
        "birth_place": ["Stuttgart"],
        "nationality": ["DE"],
        "birth_family_name": ["Smith"],
        "birth_given_name": ["Jane"],
        "personal_administrative_number": ["DE-PID-TEST-JANE"]
      },
      "credentials": [
        {
          "type": "password",
          "value": "janesmith",
          "temporary": false
        }
      ],
      "realmRoles": [
        "default-roles-gaia-x",
        "eid-holder-natural-person"
      ],
      "clientRoles": {
        "federated-catalogue": [
          "Ro-MU-CA",
          "Ro-SD-A",
          "Ro-PA-A",
          "Ro-MU-A"
        ]
      }
    },
    {
      "username": "bobjohnson",
      "enabled": true,
      "email": "bobjohnson@gaia-x.local",
      "emailVerified": true,
      "firstName": "Bob",
      "lastName": "Johnson",
      "attributes": {
        "birthdate": ["1989-11-02"],
        "gender": ["1"],
        "gender_as_string": ["male"],
        "street": ["Altonaer Strasse"],
        "address_house_number": ["44"],
        "locality": ["Hamburg"],
        "region": ["Hamburg"],
        "postal_code": ["22767"],
        "country": ["DE"],
        "birth_country": ["DE"],
        "birth_city": ["Hamburg"],
        "birth_place": ["Hamburg"],
        "nationality": ["DE"],
        "birth_family_name": ["Johnson"],
        "birth_given_name": ["Bob"],
        "personal_administrative_number": ["DE-PID-TEST-BOB"]
      },
      "credentials": [
        {
          "type": "password",
          "value": "bobjohnson",
          "temporary": false
        }
      ],
      "realmRoles": [
        "default-roles-gaia-x",
        "eid-holder-natural-person"
      ],
      "clientRoles": {
        "federated-catalogue": [
          "Ro-MU-CA",
          "Ro-SD-A",
          "Ro-PA-A",
          "Ro-MU-A"
        ]
      }
    },
    {
      "username": "alicewilliams",
      "enabled": true,
      "email": "alicewilliams@gaia-x.local",
      "emailVerified": true,
      "firstName": "Alice",
      "lastName": "Williams",
      "attributes": {
        "birthdate": ["1992-04-17"],
        "gender": ["2"],
        "gender_as_string": ["female"],
        "street": ["Rheinstrasse"],
        "address_house_number": ["12"],
        "locality": ["Berlin"],
        "region": ["Berlin"],
        "postal_code": ["12159"],
        "country": ["DE"],
        "birth_country": ["DE"],
        "birth_city": ["Berlin"],
        "birth_place": ["Berlin"],
        "nationality": ["DE"],
        "birth_family_name": ["Williams"],
        "birth_given_name": ["Alice"],
        "personal_administrative_number": ["DE-PID-TEST-ALICE"]
      },
      "credentials": [
        {
          "type": "password",
          "value": "alicewilliams",
          "temporary": false
        }
      ],
      "realmRoles": [
        "default-roles-gaia-x",
        "eid-holder-natural-person"
      ],
      "clientRoles": {
        "federated-catalogue": [
          "Ro-MU-CA",
          "Ro-SD-A",
          "Ro-PA-A",
          "Ro-MU-A"
        ]
      }
    },
    {
      "username": "charliebrown",
      "enabled": true,
      "email": "charliebrown@gaia-x.local",
      "emailVerified": true,
      "firstName": "Charlie",
      "lastName": "Brown",
      "attributes": {
        "birthdate": ["1996-06-23"],
        "gender": ["1"],
        "gender_as_string": ["male"],
        "street": ["Maximilianstrasse"],
        "address_house_number": ["8"],
        "locality": ["Munich"],
        "region": ["Bavaria"],
        "postal_code": ["80539"],
        "country": ["DE"],
        "birth_country": ["DE"],
        "birth_city": ["Munich"],
        "birth_place": ["Munich"],
        "nationality": ["DE"],
        "birth_family_name": ["Brown"],
        "birth_given_name": ["Charlie"],
        "personal_administrative_number": ["DE-PID-TEST-CHARLIE"]
      },
      "credentials": [
        {
          "type": "password",
          "value": "charliebrown",
          "temporary": false
        }
      ],
      "realmRoles": [
        "default-roles-gaia-x",
        "eid-holder-natural-person"
      ],
      "clientRoles": {
        "federated-catalogue": [
          "Ro-MU-CA",
          "Ro-SD-A",
          "Ro-PA-A",
          "Ro-MU-A"
        ]
      }
    },
    {
      "username": "saoirseconrad",
      "enabled": true,
      "email": "saoirseconrad@gaia-x.local",
      "emailVerified": true,
      "firstName": "Saoirse",
      "lastName": "Conrad",
      "attributes": {
        "birthdate": ["1994-12-01"],
        "gender": ["2"],
        "gender_as_string": ["female"],
        "street": ["Friedrichstrasse"],
        "address_house_number": ["100"],
        "locality": ["Frankfurt"],
        "region": ["Hesse"],
        "postal_code": ["60311"],
        "country": ["DE"],
        "birth_country": ["IE"],
        "birth_city": ["Dublin"],
        "birth_place": ["Dublin"],
        "nationality": ["IE"],
        "birth_family_name": ["Conrad"],
        "birth_given_name": ["Saoirse"],
        "personal_administrative_number": ["DE-PID-TEST-SAOIRSE"]
      },
      "credentials": [
        {
          "type": "password",
          "value": "saoirseconrad",
          "temporary": false
        }
      ],
      "realmRoles": [
        "default-roles-gaia-x",
        "eid-holder-natural-person"
      ],
      "clientRoles": {
        "federated-catalogue": [
          "Ro-MU-CA",
          "Ro-SD-A",
          "Ro-PA-A",
          "Ro-MU-A"
        ]
      }
    }
  ],
  "clients": [
    {
      "clientId": "federated-catalogue",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": "federated-catalogue-secret",
      "redirectUris": {{ toJson .Values.realm.dcsClient.redirectUris }},
      "webOrigins": {{ toJson .Values.realm.dcsClient.webOrigins }},
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "serviceAccountsEnabled": true,
      "authorizationServicesEnabled": true,
      "publicClient": false,
      "protocol": "openid-connect",
      "fullScopeAllowed": true,
      "protocolMappers": [
        {
          "name": "Client Host",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usersessionmodel-note-mapper",
          "config": {
            "user.session.note": "clientHost",
            "userinfo.token.claim": "true",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "clientHost",
            "jsonType.label": "String"
          }
        },
        {
          "name": "Client ID",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usersessionmodel-note-mapper",
          "config": {
            "user.session.note": "clientId",
            "userinfo.token.claim": "true",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "clientId",
            "jsonType.label": "String"
          }
        }
      ],
      "defaultClientScopes": [
        "openid",
        "profile",
        "email",
        "web-origins",
        "gaia-x",
        "roles"
      ],
      "optionalClientScopes": [
        "participant",
        "self-description",
        "offline_access"
      ],
      "authorizationSettings": {
        "allowRemoteResourceManagement": false,
        "policyEnforcementMode": "ENFORCING",
        "resources": [
          {
            "name": "Default Resource",
            "type": "urn:federated-catalogue:resources:default",
            "uris": [
              "/*"
            ]
          }
        ],
        "policies": [
          {
            "name": "Default Permission",
            "type": "resource",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "config": {
              "defaultResourceType": "urn:federated-catalogue:resources:default",
              "applyPolicies": "[]"
            }
          }
        ]
      }
    },
    {
      "clientId": "dcs-fc-client",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": "dcs-fc-client-secret",
      "standardFlowEnabled": false,
      "serviceAccountsEnabled": true,
      "publicClient": false,
      "frontchannelLogout": true,
      "protocol": "openid-connect",
      "attributes": {
        "backchannel.logout.session.required": "true"
      },
      "fullScopeAllowed": true,
      "protocolMappers": [
        {
          "name": "Client IP Address",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usersessionmodel-note-mapper",
          "consentRequired": false,
          "config": {
            "user.session.note": "clientAddress",
            "id.token.claim": "true",
            "introspection.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "clientAddress",
            "jsonType.label": "String"
          }
        },
        {
          "name": "Client ID",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usersessionmodel-note-mapper",
          "consentRequired": false,
          "config": {
            "user.session.note": "client_id",
            "id.token.claim": "true",
            "introspection.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "client_id",
            "jsonType.label": "String"
          }
        },
        {
          "name": "Client Host",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usersessionmodel-note-mapper",
          "consentRequired": false,
          "config": {
            "user.session.note": "clientHost",
            "id.token.claim": "true",
            "introspection.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "clientHost",
            "jsonType.label": "String"
          }
        }
      ],
      "defaultClientScopes": [
        "roles",
        "dcs-fc-audience"
      ],
      "optionalClientScopes": [
        "offline_access"
      ]
    },
    {
      "clientId": "pid-issuer-srv",
      "name": "PID Issuer service",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": {{ required "realm.pidIssuer.serviceClient.secret is required when realm.import=true" .Values.realm.pidIssuer.serviceClient.secret | quote }},
      "standardFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "publicClient": false,
      "protocol": "openid-connect",
      "attributes": {
        "allow.token.introspection.without.audience.check": "true"
      }
    },
    {
      "clientId": "pid-holder-python",
      "name": "Python OpenID4VCI holder",
      "enabled": true,
      "redirectUris": {{ toJson .Values.realm.pidIssuer.holderClient.redirectUris }},
      "webOrigins": {{ toJson .Values.realm.pidIssuer.holderClient.webOrigins }},
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "publicClient": true,
      "protocol": "openid-connect",
      "attributes": {
        "pkce.code.challenge.method": "S256",
        "dpop.bound.access.tokens": "true",
        "access.token.signed.response.alg": "ES256",
        "id.token.signed.response.alg": "ES256"
      },
      "defaultClientScopes": [
        "web-origins"
      ],
      "optionalClientScopes": [
        "eu.europa.ec.eudi.pid_vc_sd_jwt"
      ],
      "protocolMappers": [
        {
          "name": "client_status",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-hardcoded-claim-mapper",
          "config": {
            "claim.name": "client_status",
            "jsonType.label": "JSON",
            "claim.value": "{\"status\":{\"status_list\":{\"uri\":\"http://localhost:30822/wia-statuslists/dev-smoke\",\"idx\":0}},\"exp\":1957609682}",
            "id.token.claim": "false",
            "access.token.claim": "true",
            "userinfo.token.claim": "false",
            "access.tokenResponse.claim": "false",
            "introspection.token.claim": "true"
          }
        }
      ]
    }
  ],
  "clientScopes": [
    {
      "name": "openid",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "true"
      },
      "protocolMappers": []
    },
    {
      "name": "profile",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "true"
      },
      "protocolMappers": [
        {
          "name": "username",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-property-mapper",
          "config": {
            "user.attribute": "username",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "preferred_username",
            "userinfo.token.claim": "true"
          }
        },
        {
          "name": "full name",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-full-name-mapper",
          "config": {
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        }
      ]
    },
    {
      "name": "email",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "true"
      },
      "protocolMappers": [
        {
          "name": "email",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-property-mapper",
          "config": {
            "user.attribute": "email",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "email",
            "userinfo.token.claim": "true"
          }
        },
        {
          "name": "email verified",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-property-mapper",
          "config": {
            "user.attribute": "emailVerified",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "email_verified",
            "userinfo.token.claim": "true"
          }
        }
      ]
    },
    {
      "name": "roles",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "false",
        "display.on.consent.screen": "true"
      },
      "protocolMappers": [
        {
          "name": "realm roles",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-realm-role-mapper",
          "config": {
            "user.attribute": "foo",
            "access.token.claim": "true",
            "claim.name": "realm_access.roles",
            "jsonType.label": "String",
            "multivalued": "true"
          }
        },
        {
          "name": "client roles",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-client-role-mapper",
          "config": {
            "user.attribute": "foo",
            "access.token.claim": "true",
            "claim.name": "resource_access.${client_id}.roles",
            "jsonType.label": "String",
            "multivalued": "true"
          }
        }
      ]
    },
    {
      "name": "web-origins",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "false",
        "display.on.consent.screen": "false"
      },
      "protocolMappers": [
        {
          "name": "allowed web origins",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-allowed-origins-mapper",
          "config": {}
        }
      ]
    },
    {
      "name": "gaia-x",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true"
      },
      "protocolMappers": [
        {
          "name": "realm roles",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-realm-role-mapper",
          "config": {
            "access.token.claim": "true",
            "claim.name": "realm_access.roles",
            "jsonType.label": "String",
            "multivalued": "true"
          }
        },
        {
          "name": "client roles",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-client-role-mapper",
          "config": {
            "access.token.claim": "true",
            "claim.name": "resource_access.${client_id}.roles",
            "jsonType.label": "String",
            "multivalued": "true"
          }
        },
        {
          "name": "participant_id",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-attribute-mapper",
          "config": {
            "user.attribute": "participantId",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "participant_id",
            "userinfo.token.claim": "true"
          }
        }
      ]
    },
    {
      "name": "participant",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true"
      }
    },
    {
      "name": "self-description",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true"
      }
    },
    {
      "name": "eu.europa.ec.eudi.pid_vc_sd_jwt",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true"
      }
    },
    {
      "name": "dcs-fc-audience",
      "description": "Allows dcs-fc-client tokens to access federated-catalogue APIs",
      "protocol": "openid-connect",
      "attributes": {
        "display.on.consent.screen": "false"
      },
      "protocolMappers": [
        {
          "name": "fc-audience",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "consentRequired": false,
          "config": {
            "included.client.audience": "federated-catalogue",
            "access.token.claim": "true",
            "introspection.token.claim": "true"
          }
        }
      ]
    }
  ]
}
