# CIVOPS-Radar Mobile Installation

## Quick Start

1. **Install Termux** from F-Droid (not Google Play)
2. **Run this installer**:
   ```bash
   curl -sSL https://raw.githubusercontent.com/your-username/CIVOPS-Radar/main/termux/mobile_install.sh | bash
   ```
3. **Start the radar**:
   ```bash
   cd ~/radar
   ./start_mobile.sh
   ```
4. **Open browser** to: `http://localhost:5000`

## Mobile Commands

- `./start_mobile.sh` - Start full radar system
- `./quick_start.sh` - Quick web interface only
- `./update_radar.sh` - Update from GitHub
- `./termux/radar_prototype.sh scan` - Scanner only

## Mobile Features

- 📱 **Mobile-optimized interface**
- 🛰️ **Live radar visualization**
- 📊 **Real-time statistics**
- 📤 **Data export**
- 🔒 **Offline operation**

## Troubleshooting

### No Networks Detected
- Check location permissions
- Ensure Wi-Fi is enabled
- Try increasing scan interval

### Web Interface Not Loading
- Check if port 5000 is available
- Restart with `./quick_start.sh`
- Check firewall settings

### Update Issues
- Run `./update_radar.sh`
- Check internet connection
- Verify GitHub access

## Support

- 📖 Documentation: [GitHub](https://github.com/your-username/CIVOPS-Radar)
- 🐛 Issues: [GitHub Issues](https://github.com/your-username/CIVOPS-Radar/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/your-username/CIVOPS-Radar/discussions)

---

**Happy scanning! 🛰️**
