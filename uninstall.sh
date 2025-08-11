echo "WARNING: Please check these path are correct !"
echo "Will delete : $(pwd) in 15 seconds"
echo "Will delete : ../_oqs in 15 seconds"
echo "Will executed : pip uninstall liboqs-python in 15 seconds"
echo "CTRL+C to cancel"
sleep 15
pip uninstall liboqs-python
sudo rm -rf ../_oqs
sudo rm -rf $(pwd)