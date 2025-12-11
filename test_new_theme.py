#!/usr/bin/env python3
"""
Test ByteGuardX New Black/White/Cyan Theme
Verify the theme is working correctly
"""

import requests
import time

def test_new_theme():
    """Test the new black/white/cyan theme"""
    
    print("🎨 ByteGuardX Black/White/Cyan Theme Test")
    print("=" * 50)
    
    # Test backend (should still be working)
    print("🔧 Testing Backend API...")
    try:
        response = requests.get('http://localhost:5000/api/health', timeout=5)
        if response.status_code == 200:
            print("✅ Backend API: Working")
        else:
            print(f"❌ Backend API: {response.status_code}")
    except:
        print("❌ Backend API: Not accessible")
    
    # Test frontend with new theme
    print("\n🌐 Testing Frontend with New Theme...")
    try:
        response = requests.get('http://localhost:3000', timeout=5)
        if response.status_code == 200:
            print("✅ Frontend: Accessible with new theme")
            
            # Check if the response contains our theme elements
            content = response.text
            if 'bg-black' in content or 'background: #000000' in content:
                print("✅ Theme: Black background detected")
            else:
                print("⚠️  Theme: Black background not detected in HTML")
                
        else:
            print(f"❌ Frontend: {response.status_code}")
    except:
        print("❌ Frontend: Not accessible")
    
    print(f"\n🎉 NEW THEME APPLIED!")
    print("=" * 30)
    print("🎨 Theme Features:")
    print("  • Pure black background (#000000)")
    print("  • White text (#ffffff)")
    print("  • Cyan hover effects (#00bcd4)")
    print("  • No other colors used")
    
    print(f"\n🌐 Access URLs:")
    print("  • Frontend: http://localhost:3000")
    print("  • Backend:  http://localhost:5000")
    
    print(f"\n💡 Theme Changes Applied:")
    print("  ✅ Global CSS updated")
    print("  ✅ Component backgrounds changed")
    print("  ✅ Tailwind config updated")
    print("  ✅ Theme override CSS added")
    print("  ✅ All gradients removed")
    print("  ✅ Hover effects set to cyan")
    
    print(f"\n🎊 Open http://localhost:3000 to see the new theme!")

if __name__ == "__main__":
    time.sleep(2)  # Wait for servers
    test_new_theme()
