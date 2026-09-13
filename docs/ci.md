# CI guidance

Open Envault is provider-neutral. CI needs the committed encrypted profile and
the matching private age identity in its own secret store.

For GitHub Actions, create the repository `production` Environment and add the
private identity as `SOPS_AGE_KEY` through GitHub’s UI or approved repository
administration tooling. Do not commit the identity or put it in workflow source.

```yaml
- uses: actions/checkout@v4
- name: Install oenv
  run: cargo install open-envault
- name: Validate production profile
  env:
    SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}
  run: oenv check prd
- name: Run service
  env:
    SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}
  run: oenv exec prd -- ./service
```

Open Envault does not create GitHub Environments or Secrets and has no required
secret-provider dependency. CI tests use fake fixture keys only; real
production values and identities remain in the CI secret manager.
