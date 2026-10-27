# How to install
Packages are available do download with GitHub package repository, but not with Maven Repository - at least not yet.

## Two ways to install.

### Download with GitHub packages
1. Go to `.m2/settings.xml` file and add repository. If there is no such file, create one.
```xml
<repository>
    <id>gh-ys-j-key-store</id>
    <url>https://maven.pkg.github.com/Ysdaeth/j-key-store</url>
</repository>
```

### Alternatively, download repository and install locally
```shell
git clone https://github.com/Ysdaeth/j-key-store.git
cd j-key-store
sudo mvn clean install
```