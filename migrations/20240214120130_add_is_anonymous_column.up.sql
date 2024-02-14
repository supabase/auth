do $$
begin
   alter table {{ index .Options "Namespace" }}.users 
   add column if not exists is_anonymous boolean generated always as (
    case 
        when (email is null or email = '') and (phone is null or phone = '') then true
        else false
    end 
   ) stored;
end
$$;
