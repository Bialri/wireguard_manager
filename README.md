
<h2>Tests</h2>
Due to the specifics of the package testing environment, the tests are run in a docker container. To create an environment, build an image from test.Dockerfile

```shell
docker build -f test.Dockerfile -t wireguard_manager_test_enviroment .
```

And run container with mounted src to ```/tests/src``` and tests to ```/tests``` directories

```shell
docker container run --cap-add=NET_ADMIN --name test -v ./src:/tests/src  -v ./tests:/tests wireguard_manager_test
```
