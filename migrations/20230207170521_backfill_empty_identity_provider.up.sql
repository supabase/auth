update {{ index .Options "Namespace" }}.identities
  set
    provider = identity_data->>'iss'
  where
    provider = '' and 
    identity_data->>'iss' is not null and 
    identity_data->>'iss' != '';
