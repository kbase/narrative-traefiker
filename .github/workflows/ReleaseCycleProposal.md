## New PR & Testing Process Proposal

(Will start at the end of the cycle, as it oddly makes things more clear)

### Release Cycle Pt. 1:

- An official "release" (version bump) is merged from develop to master.
- The production Docker image `<appname>:latest` is then updated and pushed to GitHub Packages.
- After this release update is complete, a new Draft/WIP PR for the next release is created (again a merge from develop to master). 

### Develop Cycle:

- Once development on a new release begins, developers create their short-lived feature branches off of develop.
- Once their feature is complete, they create a new PR to merge from their feature branch to develop.
- Once this PR is created, an `<appname>-test:pr#` image is uploaded to GitHub Packages.
    - Note that this image is intentionally separate from the prod `<appname>` image.
- (Optional) - Once the `<appname>-test:pr#` image build & upload is complete, some process (PR labeling or a PR comment) "enables" this image to be tested in appdev, ci, and/or next.
- Through some process, we test the image in these environments.
    - Note that if we simply use the `<appname>-test:pr#` nomenclature, the above "test environment enabling" may not be needed. 
    - Simply specifying which PR# tag you want to pull in each environment would suffice.
- Once all testing is complete, the code is merged to develop.

### Release Cycle Pt. 2

- Once all development for a release is complete, the aforementioned "Release PR" (aka the long-running Draft/WIP PR that will merge from develop to master) is taken out of WIP/Draft mode.
- Taking the Release PR out of Draft/WIP will trigger one final build test from the develop branch.
- Once this image has passed the initial build test, the repo owner can merge the Release PR to master.
- Once merged, the final build image will be uploaded to the prod `<appname>:latest` image.
- Process starts again by creating a new Draft/WIP Release PR for the next release.

#### Advantages

- Using the `<appname>-test:pr#` naming scheme allows us to test multiple feature improvements at will, allowing for higher velocity development.
- Separating features in this way allows us to run build tests on smaller changes, reducing errors.
- The final Release PR build ensures that the final production image still builds correctly without error.
- Keeping separate prod & `-test` images keeps the prod image clean, with a maximum of 2 tags (`latest` & possibly `rc` or `release-candidate`).
- Although the `-test` image will have a fair number of tags, it's extremely easy to pull the correct test image by simply specifying the `:PR#` tag.
