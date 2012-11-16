from handlers import Handler

# ===========================================
class ProfileHandler(Handler):
    def render_front(self, entries={}):
        self.render('mockup_profile.html')

    def get(self):
        self.render_front()


# ===========================================
class HistoryHandler(Handler):
    def render_front(self, entries={}):
        self.render('mockup_history.html')

    def get(self):
        self.render_front()

# ===========================================
class InsuranceHandler(Handler):
    def render_front(self, entries={}):
        self.render('mockup_insurance.html')

    def get(self):
        self.render_front()

# ===========================================
class DashboardHandler(Handler):
    def render_front(self, entries={}):
        self.render('mockup_dashboard.html')

    def get(self):
        self.render_front()

